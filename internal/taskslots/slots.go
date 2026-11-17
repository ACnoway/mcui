// Package taskslots stores task reservation intent in a separate SQLite database.
// It does not authenticate callers, sign tasks, or deliver them. In particular,
// callers must authenticate and authorize completion before calling Complete.
package taskslots

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// MaxSequence is the largest integer representable exactly by the v1 protocol.
const MaxSequence int64 = 9007199254740991

var ErrConflict = errors.New("task slot conflict")
var ErrNotFound = errors.New("task slot not found")

// Slot is an immutable reservation. Complete marks its active state terminal.
type Slot struct {
	NodeID   string
	TaskID   string
	Sequence int64
	Intent   []byte
	Complete bool
}
type Store struct{ db *sql.DB }

// Init exclusively creates a new database. It never overwrites an existing file.
func Init(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	s, err := connect(path)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`BEGIN IMMEDIATE;
 CREATE TABLE metadata (version INTEGER NOT NULL CHECK(version=1));
 INSERT INTO metadata VALUES (1);
 CREATE TABLE slots (task_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence > 0), intent BLOB NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)), UNIQUE(node_id, sequence));
 CREATE UNIQUE INDEX one_active_per_node ON slots(node_id) WHERE completed=0;
 COMMIT;`)
	if err != nil {
		s.Close()
		return nil, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		s.Close()
		return nil, err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		s.Close()
		return nil, errors.Join(err, closeErr)
	}
	return s, nil
}

// Open opens an initialized database, never creating a missing one.
func Open(path string) (*Store, error) {
	s, err := connect(path)
	if err != nil {
		return nil, err
	}
	var version, count int
	err = s.db.QueryRow(`SELECT COALESCE(MAX(version),0), COUNT(*) FROM metadata`).Scan(&version, &count)
	if err != nil || version != 1 || count != 1 {
		s.Close()
		return nil, fmt.Errorf("invalid task slot database: version=%d count=%d: %v", version, count, err)
	}
	// Only accept the schema created by this version, including its constraints.
	type schemaObject struct {
		typ, table string
		definition sql.NullString
	}
	expected := map[string]schemaObject{
		"metadata":                 {"table", "metadata", sql.NullString{String: `CREATE TABLE metadata (version INTEGER NOT NULL CHECK(version=1))`, Valid: true}},
		"slots":                    {"table", "slots", sql.NullString{String: `CREATE TABLE slots (task_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence > 0), intent BLOB NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)), UNIQUE(node_id, sequence))`, Valid: true}},
		"one_active_per_node":      {"index", "slots", sql.NullString{String: `CREATE UNIQUE INDEX one_active_per_node ON slots(node_id) WHERE completed=0`, Valid: true}},
		"sqlite_autoindex_slots_1": {"index", "slots", sql.NullString{}},
		"sqlite_autoindex_slots_2": {"index", "slots", sql.NullString{}},
	}
	rows, err := s.db.Query(`SELECT name, type, tbl_name, sql FROM sqlite_master`)
	if err != nil {
		s.Close()
		return nil, err
	}
	valid := true
	seen := 0
	for rows.Next() {
		var name string
		var object schemaObject
		if rows.Scan(&name, &object.typ, &object.table, &object.definition) != nil || expected[name] != object {
			valid = false
		}
		seen++
	}
	if rows.Err() != nil {
		valid = false
	}
	rows.Close()
	if !valid || seen != len(expected) {
		s.Close()
		return nil, errors.New("invalid task slot schema")
	}
	var invalid int
	err = s.db.QueryRow(`SELECT
 (SELECT COUNT(*) FROM slots WHERE typeof(node_id) != 'text' OR length(CAST(node_id AS BLOB)) = 0
 OR typeof(task_id) != 'text' OR length(CAST(task_id AS BLOB)) = 0
 OR typeof(intent) != 'blob' OR length(intent) = 0
 OR typeof(sequence) != 'integer' OR sequence < 1 OR sequence > ?
 OR typeof(completed) != 'integer' OR completed NOT IN (0,1)) +
 (SELECT COUNT(*) FROM (
 SELECT node_id FROM slots GROUP BY node_id
 HAVING MIN(sequence) != 1 OR MAX(sequence) != COUNT(*)
 OR MAX(CASE WHEN completed=0 THEN sequence ELSE 0 END) NOT IN (0, MAX(sequence))
 ))`, MaxSequence).Scan(&invalid)
	if err != nil || invalid != 0 {
		s.Close()
		return nil, fmt.Errorf("invalid task slot history: invalid nodes=%d: %v", invalid, err)
	}
	return s, nil
}
func connect(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(EXTRA)")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	var mode string
	var synchronous int
	if err = db.QueryRow("PRAGMA journal_mode").Scan(&mode); err == nil {
		err = db.QueryRow("PRAGMA synchronous").Scan(&synchronous)
	}
	if err != nil || mode != "delete" || synchronous != 3 {
		db.Close()
		return nil, fmt.Errorf("unsafe SQLite settings: journal=%q synchronous=%d: %v", mode, synchronous, err)
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }

// Complete records a terminal outcome after external authentication and
// authorization. It never validates the caller's identity itself.
// transaction owns its connection until rollback or commit is confirmed.
func (s *Store) transaction(f func(*sql.Conn) error) (result error) {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		conn.Raw(func(any) error { return driver.ErrBadConn })
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
				conn.Raw(func(any) error { return driver.ErrBadConn })
				result = errors.Join(result, fmt.Errorf("task slots rollback: %w", err))
			}
		}
	}()
	if err = f(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Store) Complete(nodeID, taskID string, sequence int64) error {
	return s.transaction(func(tx *sql.Conn) error {
		result, err := tx.ExecContext(context.Background(), `UPDATE slots SET completed=1 WHERE node_id=? AND task_id=? AND sequence=?`, nodeID, taskID, sequence)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// Reserve atomically assigns the next sequence for a node and retains exact
// intent bytes. Task IDs are globally unique, including after completion.
// An exact retry returns the original slot, including its completion state.
func (s *Store) Reserve(nodeID, taskID string, intent []byte) (Slot, error) {
	if nodeID == "" || taskID == "" || len(intent) == 0 {
		return Slot{}, errors.New("node, task and intent are required")
	}
	var out Slot
	err := s.transaction(func(tx *sql.Conn) error {
		ctx := context.Background()
		var slot Slot
		var done int
		err := tx.QueryRowContext(ctx, `SELECT node_id,task_id,sequence,intent,completed FROM slots WHERE task_id=?`, taskID).Scan(&slot.NodeID, &slot.TaskID, &slot.Sequence, &slot.Intent, &done)
		if err == nil {
			slot.Complete = done != 0
			if slot.NodeID != nodeID || !bytes.Equal(slot.Intent, intent) {
				return ErrConflict
			}
			out = slot
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM slots WHERE node_id=? AND completed=0`, nodeID).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return ErrConflict
		}
		var seq int64
		if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0) FROM slots WHERE node_id=?`, nodeID).Scan(&seq); err != nil {
			return err
		}
		if seq >= MaxSequence {
			return errors.New("sequence exhausted")
		}
		seq++
		if _, err = tx.ExecContext(ctx, `INSERT INTO slots(task_id,node_id,sequence,intent,completed) VALUES(?,?,?,?,0)`, taskID, nodeID, seq, intent); err != nil {
			return err
		}
		out = Slot{NodeID: nodeID, TaskID: taskID, Sequence: seq, Intent: bytes.Clone(intent)}
		return nil
	})
	if err != nil {
		return Slot{}, err
	}
	return out, nil
}
