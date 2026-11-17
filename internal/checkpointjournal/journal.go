// Package checkpointjournal implements an experimental local SQLite journal.
// It provides no authentication, integrity against attackers, or anti-rollback.
// A trusted private directory is required; pathname checks are not race-proof.
// Machine operations still require exclusive ownership across the entire operation.
// SQLite uses DELETE rollback journals and synchronous=EXTRA; existing WAL or
// other journal modes are rejected rather than migrated. Durability depends on
// correct filesystem, storage, and sync behavior; no power-cut testing is implied.
package checkpointjournal

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const schema = `CREATE TABLE journal (id INTEGER PRIMARY KEY CHECK (id = 1), committed BLOB NOT NULL, intent BLOB) STRICT`

var ErrInvalid = errors.New("invalid checkpoint journal or request")

type Journal struct{ db *sql.DB }

var _ checkpoint.Journal = (*Journal)(nil)

func valid(r checkpoint.Record) bool {
	return r.Node != "" && utf8.ValidString(r.Node) && r.Epoch != 0 && r.Digest != ([32]byte{})
}
func validIntent(i checkpoint.Intent) bool {
	return valid(i.Previous) && valid(i.Next) && i.Previous.Node == i.Next.Node && i.Previous.Epoch == i.Next.Epoch && i.Previous.Revision < math.MaxUint64 && i.Next.Revision == i.Previous.Revision+1
}
func checkFile(path string, create bool) error {
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	fd, err := unix.Open(path, flags, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var s unix.Stat_t
	if err = unix.Fstat(fd, &s); err != nil {
		return err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0777 != 0600 || s.Nlink != 1 {
		return ErrInvalid
	}
	return nil
}
func connect(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "synchronous(EXTRA)")
	q.Add("_pragma", "busy_timeout(10000)")
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
	// Do not silently switch an existing database, especially a WAL database
	// with sidecars. SQLite's EXTRA is needed for DELETE-mode directory sync.
	var mode string
	var synchronous int
	if err = db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err == nil {
		err = db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	if mode != "delete" || synchronous != 3 {
		db.Close()
		return nil, fmt.Errorf("%w: unsafe SQLite journal mode %q or synchronous level %d", ErrInvalid, mode, synchronous)
	}
	return db, nil
}

// Create exclusively creates a journal. A failure may leave an unusable file;
// existing files are never reset. The containing directory must already exist.
func Create(path string, initial checkpoint.Record) (*Journal, error) {
	if !valid(initial) {
		return nil, ErrInvalid
	}
	if err := checkFile(path, true); err != nil {
		return nil, err
	}
	db, err := connect(path)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Journal, error) { db.Close(); return nil, e }
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	b, _ := json.Marshal(initial)
	if _, err = tx.Exec(schema); err != nil {
		return fail(err)
	}
	if _, err = tx.Exec(`INSERT INTO journal VALUES (1,?,NULL)`, b); err != nil {
		return fail(err)
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fail(err)
	}
	err = d.Sync()
	closeErr := d.Close()
	if err != nil {
		return fail(err)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	return &Journal{db}, nil
}

// Open rejects absent, uninitialized, malformed, and unexpected schemas.
func Open(path string) (*Journal, error) {
	if err := checkFile(path, false); err != nil {
		return nil, err
	}
	db, err := connect(path)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Journal, error) { db.Close(); return nil, e }
	var count int
	var got string
	if err = db.QueryRow(`SELECT count(*) FROM sqlite_master`).Scan(&count); err != nil {
		return fail(err)
	}
	if count != 1 {
		return fail(ErrInvalid)
	}
	if err = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='journal'`).Scan(&got); err != nil {
		return fail(err)
	}
	if got != schema {
		return fail(ErrInvalid)
	}
	if err = db.QueryRow(`PRAGMA integrity_check`).Scan(&got); err != nil {
		return fail(err)
	}
	if got != "ok" {
		return fail(ErrInvalid)
	}
	j := &Journal{db}
	if _, err = j.Load(context.Background()); err != nil {
		return fail(err)
	}
	return j, nil
}
func (j *Journal) Close() error { return j.db.Close() }

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func load(ctx context.Context, q queryer) (checkpoint.State, error) {
	var s checkpoint.State
	var b, i []byte
	var count int
	if err := q.QueryRowContext(ctx, `SELECT committed,intent,(SELECT count(*) FROM journal) FROM journal WHERE id=1`).Scan(&b, &i, &count); err != nil {
		return s, err
	}
	if count != 1 {
		return s, ErrInvalid
	}
	if err := json.Unmarshal(b, &s.Committed); err != nil || !valid(s.Committed) {
		return checkpoint.State{}, ErrInvalid
	}
	if i != nil {
		var in checkpoint.Intent
		if err := json.Unmarshal(i, &in); err != nil || !validIntent(in) || in.Previous != s.Committed {
			return checkpoint.State{}, ErrInvalid
		}
		s.Intent = &in
	}
	return s, nil
}
func (j *Journal) Load(ctx context.Context) (checkpoint.State, error) { return load(ctx, j.db) }

// Mutation errors can have unknown outcomes; reload and reconcile before use.
func (j *Journal) Begin(ctx context.Context, expected checkpoint.Record, i checkpoint.Intent) error {
	if !validIntent(i) || expected != i.Previous {
		return ErrInvalid
	}
	return j.mutate(ctx, func(s checkpoint.State) (checkpoint.Record, *checkpoint.Intent, error) {
		if s.Committed != expected || s.Intent != nil {
			return checkpoint.Record{}, nil, ErrInvalid
		}
		return s.Committed, &i, nil
	})
}
func (j *Journal) Commit(ctx context.Context, i checkpoint.Intent) error {
	if !validIntent(i) {
		return ErrInvalid
	}
	return j.mutate(ctx, func(s checkpoint.State) (checkpoint.Record, *checkpoint.Intent, error) {
		if s.Intent == nil || *s.Intent != i || s.Committed != i.Previous {
			return checkpoint.Record{}, nil, ErrInvalid
		}
		return i.Next, nil, nil
	})
}
func (j *Journal) mutate(ctx context.Context, f func(checkpoint.State) (checkpoint.Record, *checkpoint.Intent, error)) (result error) {
	conn, err := j.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// database/sql's Tx.Commit makes the Tx unusable even if SQLite leaves
	// the transaction open after a failed COMMIT. Own the connection until a
	// rollback succeeds, and discard it if cleanup cannot be confirmed.
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		// A failed BEGIN can also have an uncertain outcome.
		conn.Raw(func(any) error { return driver.ErrBadConn })
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if _, rollbackErr := conn.ExecContext(context.Background(), `ROLLBACK`); rollbackErr != nil {
				conn.Raw(func(any) error { return driver.ErrBadConn })
				result = errors.Join(result, fmt.Errorf("journal rollback: %w", rollbackErr))
			}
		}
	}()
	s, err := load(ctx, conn)
	if err != nil {
		return err
	}
	r, i, err := f(s)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	var ib any
	if i != nil {
		ib, _ = json.Marshal(i)
	}
	if _, err = conn.ExecContext(ctx, `UPDATE journal SET committed=?,intent=? WHERE id=1`, b, ib); err != nil {
		return fmt.Errorf("journal mutation: %w", err)
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}
