package lifecycleauth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

const ledgerSchema = `CREATE TABLE issuances (
 task_id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence >= 1 AND sequence <= 9007199254740991),
 approval_id TEXT NOT NULL UNIQUE CHECK(length(approval_id) = 64),
 evidence BLOB NOT NULL CHECK(length(evidence) BETWEEN 1 AND 16384),
 task BLOB NOT NULL CHECK(length(task) BETWEEN 1 AND 65536),
 UNIQUE(node_id, sequence)
) STRICT`

// Ledger belongs to the signing authority. In isolated deployments, keep it
// outside the panel's access and backup domain.
type Ledger struct{ db *sql.DB }

// InitLedger exclusively initializes a new issuance ledger.
func InitLedger(path string) error {
	abs, err := protectedLedgerPath(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	db, err := openDatabase(abs)
	if err != nil {
		return err
	}
	_, err = db.Exec(ledgerSchema)
	if err = errors.Join(err, db.Close()); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(filepath.Dir(abs))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// OpenLedger opens an initialized private ledger. Missing ledgers fail closed.
func OpenLedger(path string) (*Ledger, error) {
	abs, err := protectedLedgerPath(path)
	if err != nil {
		return nil, err
	}
	db, err := openDatabase(abs)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Ledger, error) {
		_ = db.Close()
		return nil, e
	}
	var schema, integrity string
	var objects int
	if err := db.QueryRow(`SELECT sql, (SELECT count(*) FROM sqlite_schema) FROM sqlite_schema WHERE name='issuances' AND type='table'`).Scan(&schema, &objects); err != nil {
		return fail(err)
	}
	if schema != ledgerSchema || objects != 4 {
		return fail(errors.New("unexpected Xray issuance ledger schema"))
	}
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fail(err)
	}
	if integrity != "ok" {
		return fail(errors.New("Xray issuance ledger is damaged"))
	}
	return &Ledger{db: db}, nil
}

func protectedLedgerPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("missing issuance ledger path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := os.Lstat(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	if !dir.IsDir() || (runtime.GOOS != "windows" && dir.Mode().Perm()&0022 != 0) {
		return "", errors.New("Xray issuance ledger needs a protected directory")
	}
	return abs, nil
}

func openDatabase(abs string) (*sql.DB, error) {
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		return nil, errors.New("Xray issuance ledger must be a private regular file")
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
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
	// A connection with a failed COMMIT must never be reused.
	db.SetMaxIdleConns(0)
	var mode string
	var syncLevel int
	if err = db.QueryRow("PRAGMA journal_mode").Scan(&mode); err == nil {
		err = db.QueryRow("PRAGMA synchronous").Scan(&syncLevel)
	}
	if err != nil || mode != "delete" || syncLevel != 3 {
		_ = db.Close()
		return nil, fmt.Errorf("unsafe Xray issuance ledger settings (mode=%q, synchronous=%d): %v", mode, syncLevel, err)
	}
	return db, nil
}

func (l *Ledger) Close() error { return l.db.Close() }

func (l *Ledger) consume(ctx context.Context, p Proposal, id string, evidence, task []byte) ([]byte, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO issuances VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		p.TaskID, p.NodeID, p.Sequence, id, evidence, task)
	if err != nil {
		return nil, err
	}
	var savedEvidence, savedTask []byte
	err = tx.QueryRowContext(ctx, `SELECT evidence, task FROM issuances WHERE task_id=? AND node_id=? AND sequence=? AND approval_id=?`,
		p.TaskID, p.NodeID, p.Sequence, id).Scan(&savedEvidence, &savedTask)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(evidence, savedEvidence) || !bytes.Equal(task, savedTask) {
		return nil, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return savedTask, nil
}
