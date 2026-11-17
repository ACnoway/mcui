// Package taskledger provides a local replay ledger. It does not authorize tasks.
package taskledger

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type Ledger struct {
	db   *sql.DB
	lock *os.File
}

var ledgerSchema = map[string]string{
	"metadata":      `CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, next_seq INTEGER NOT NULL)`,
	"tasks":         `CREATE TABLE tasks (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, envelope BLOB NOT NULL, not_before INTEGER NOT NULL, expires INTEGER NOT NULL, state TEXT NOT NULL, result BLOB)`,
	"cancellations": `CREATE TABLE cancellations (seq INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, envelope BLOB)`,
	"quarantine":    `CREATE TABLE quarantine (id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT NOT NULL)`,
}

// Initialize creates a new ledger only. Never use this to recover missing state.
func Initialize(path string) (*Ledger, error) {
	if err := checkDir(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	l, err := connect(path)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"metadata", "tasks", "cancellations", "quarantine"} {
		if _, err = l.db.Exec(ledgerSchema[name]); err != nil {
			l.Close()
			return nil, err
		}
	}
	_, err = l.db.Exec(`INSERT INTO metadata VALUES(1,1,1)`)
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Open requires an existing initialized ledger, and does not recreate it.
func Open(path string) (*Ledger, error) {
	l, err := connect(path)
	if err != nil {
		return nil, err
	}
	if err = validateSchema(l.db); err != nil {
		l.Close()
		return nil, fmt.Errorf("invalid ledger schema: %w", err)
	}
	var version int
	var next int64
	err = l.db.QueryRow(`SELECT version,next_seq FROM metadata WHERE id=1`).Scan(&version, &next)
	if err != nil || version != 1 || next < 1 {
		l.Close()
		return nil, fmt.Errorf("invalid ledger metadata: version=%d next=%d: %v", version, next, err)
	}
	var quarantined int
	if err = l.db.QueryRow(`SELECT COUNT(*) FROM quarantine`).Scan(&quarantined); err != nil || quarantined != 0 {
		l.Close()
		return nil, fmt.Errorf("ledger quarantined or quarantine state unavailable: %v", err)
	}
	var count, invalid int64
	err = l.db.QueryRow(`SELECT COUNT(CASE WHEN seq<? THEN 1 END), COALESCE(SUM(CASE WHEN
 seq<1 OR seq>? OR id='' OR length(envelope)=0 OR length(envelope)>65536 OR not_before>=expires OR
 (seq<? AND state NOT IN ('EXPIRED','CANCELED','SUCCEEDED','FAILED')) OR
 (seq=? AND state NOT IN ('PENDING','RUNNING','NEEDS_RECONCILIATION'))
 THEN 1 ELSE 0 END),0) FROM tasks`, next, next, next, next).Scan(&count, &invalid)
	if err != nil || invalid != 0 || count != next-1 {
		l.Close()
		return nil, fmt.Errorf("invalid ledger task continuity or state: %v", err)
	}
	var badCancels int64
	err = l.db.QueryRow(`SELECT COUNT(*) FROM cancellations c LEFT JOIN tasks t ON c.seq=t.seq
 WHERE c.seq<1 OR c.id='' OR (c.envelope IS NULL OR length(c.envelope)=0 OR length(c.envelope)>65536) OR (t.seq IS NOT NULL AND (t.id<>c.id OR t.state<>'CANCELED')) OR (c.seq<? AND t.seq IS NULL) OR EXISTS (SELECT 1 FROM tasks other WHERE other.id=c.id AND other.seq<>c.seq)`, next).Scan(&badCancels)
	if err == nil && badCancels == 0 {
		err = l.db.QueryRow(`SELECT COUNT(*) FROM tasks t LEFT JOIN cancellations c ON t.seq=c.seq WHERE t.state='CANCELED' AND c.seq IS NULL`).Scan(&badCancels)
	}
	if err != nil || badCancels != 0 {
		l.Close()
		return nil, fmt.Errorf("invalid cancellation state: %v", err)
	}
	// The lifetime lock excludes a live worker before recovery fences its state.
	if _, err = l.db.Exec(`UPDATE tasks SET state='NEEDS_RECONCILIATION' WHERE state='RUNNING'`); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// validateSchema rejects substituted tables, constraints, indexes, triggers, and
// other schema objects. Exact DDL intentionally fails closed on schema drift.
func validateSchema(db *sql.DB) error {
	rows, err := db.Query(`SELECT type, name, tbl_name, sql FROM sqlite_schema`)
	if err != nil {
		return err
	}
	defer rows.Close() // Release the only connection before Open closes the DB.
	seen := make(map[string]bool)
	for rows.Next() {
		var typ, name, table string
		var ddl sql.NullString
		if err := rows.Scan(&typ, &name, &table, &ddl); err != nil {
			return err
		}
		if seen[name] {
			return fmt.Errorf("duplicate object %q", name)
		}
		seen[name] = true
		if expected, ok := ledgerSchema[name]; ok && typ == "table" && table == name && ddl.Valid && ddl.String == expected {
			continue
		}
		if typ == "index" && !ddl.Valid && ((name == "sqlite_autoindex_tasks_1" && table == "tasks") || (name == "sqlite_autoindex_cancellations_1" && table == "cancellations")) {
			continue
		}
		return fmt.Errorf("unexpected or modified object %q", name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range []string{"metadata", "tasks", "cancellations", "quarantine", "sqlite_autoindex_tasks_1", "sqlite_autoindex_cancellations_1"} {
		if !seen[name] {
			return fmt.Errorf("missing object %q", name)
		}
	}
	for _, table := range []string{"tasks", "cancellations"} {
		if err := validateIDIndex(db, table); err != nil {
			return err
		}
	}
	return nil
}

func validateIDIndex(db *sql.DB, table string) error {
	// Table names are fixed above; PRAGMA does not accept bound identifiers.
	rows, err := db.Query(`PRAGMA index_list(` + table + `)`)
	if err != nil {
		return err
	}
	var count int
	for rows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err = rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			break
		}
		count++
		if name != "sqlite_autoindex_"+table+"_1" || unique != 1 || origin != "u" || partial != 0 {
			err = fmt.Errorf("invalid index for %s", table)
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if count != 1 {
		return fmt.Errorf("invalid index count for %s", table)
	}
	rows, err = db.Query(`PRAGMA index_xinfo(sqlite_autoindex_` + table + `_1)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	count = 0
	for rows.Next() {
		var seq, cid, desc, key int
		var name, coll sql.NullString
		if err := rows.Scan(&seq, &cid, &name, &desc, &coll, &key); err != nil {
			return err
		}
		count++
		if count == 1 && seq == 0 && cid == 1 && name.Valid && name.String == "id" && desc == 0 && coll.Valid && coll.String == "BINARY" && key == 1 {
			continue
		}
		if count == 2 && seq == 1 && cid == -1 && !name.Valid && desc == 0 && coll.Valid && coll.String == "BINARY" && key == 0 {
			continue
		}
		return fmt.Errorf("invalid index columns for %s", table)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != 2 {
		return fmt.Errorf("invalid index columns for %s", table)
	}
	return nil
}

func checkDir(path string) error {
	d, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !d.IsDir() || d.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("ledger directory must be private and not a symlink")
	}
	return nil
}

func connect(path string) (*Ledger, error) {
	if err := checkDir(path); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("ledger must be a private regular file")
	}
	lock, err := os.OpenFile(abs, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("ledger already owned or lock unavailable: %w", err)
	}
	lockedInfo, err := lock.Stat()
	if err != nil || !os.SameFile(fi, lockedInfo) {
		lock.Close()
		return nil, fmt.Errorf("ledger changed while locking")
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		lock.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		lock.Close()
		return nil, err
	}
	return &Ledger{db: db, lock: lock}, nil
}
func (l *Ledger) Close() error {
	if err := l.db.Close(); err != nil {
		return err
	}
	return l.lock.Close()
}
