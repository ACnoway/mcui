// Package checkpointstore provides an experimental SQLite checkpoint storage
// primitive for the checkpoint authority. Echoing a challenge neither
// authenticates a caller nor protects responses from forgery.
// Deployments must independently provide authenticated transport, secure identity,
// request authorization, separately administered durable storage, and anti-rollback
// protection. Use a trusted, access-controlled directory: pathname checks cannot
// defend against a privileged or concurrent attacker replacing directory entries.
// SQLite uses DELETE journals and synchronous=EXTRA. Durability depends on the
// filesystem, storage, and sync behavior; no power-cut testing is implied.
package checkpointstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const schema = `CREATE TABLE checkpoint (id INTEGER PRIMARY KEY CHECK (id = 1), node TEXT NOT NULL, epoch BLOB NOT NULL, revision BLOB NOT NULL, digest BLOB NOT NULL) STRICT`

var ErrInvalid = errors.New("invalid checkpoint store or request")

type Store struct{ db *sql.DB }

var _ checkpoint.Authority = (*Store)(nil)

func valid(r checkpoint.Record) bool { return r.Node != "" && r.Epoch != 0 && r.Digest != ([32]byte{}) }
func number(n uint64) []byte         { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func connection(path string) (*sql.DB, error) {
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
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0777 != 0600 || stat.Nlink != 1 {
		return fmt.Errorf("%w: file must be a private regular file", ErrInvalid)
	}
	return nil
}

// Create exclusively initializes a new store. Failure may leave an unusable file;
// neither Create nor Open ever resets an existing file.
func Create(path string, initial checkpoint.Record) (*Store, error) {
	if !valid(initial) {
		return nil, ErrInvalid
	}
	if err := checkFile(path, true); err != nil {
		return nil, err
	}
	db, err := connection(path)
	if err != nil {
		return nil, err
	}
	tx, err := db.Begin()
	if err == nil {
		_, err = tx.Exec(schema)
		if err == nil {
			_, err = tx.Exec(`INSERT INTO checkpoint VALUES (1,?,?,?,?)`, initial.Node, number(initial.Epoch), number(initial.Revision), initial.Digest[:])
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		db.Close()
		return nil, err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		db.Close()
		return nil, err
	}
	if closeErr != nil {
		db.Close()
		return nil, closeErr
	}
	return &Store{db}, nil
}

// Open accepts only an initialized store with the exact expected schema.
func Open(path string) (*Store, error) {
	if err := checkFile(path, false); err != nil {
		return nil, err
	}
	db, err := connection(path)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	var count int
	var got string
	// This schema creates no indexes or SQLite-owned objects, so require the
	// entire schema to contain only the expected table. In particular, do not
	// use LIKE 'sqlite_%': '_' is a wildcard, not a literal underscore.
	if err = db.QueryRow(`SELECT count(*) FROM sqlite_schema`).Scan(&count); err != nil {
		return fail(err)
	}
	if count != 1 {
		return fail(ErrInvalid)
	}
	if err = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='checkpoint'`).Scan(&got); err != nil {
		return fail(err)
	}
	if got != schema {
		return fail(ErrInvalid)
	}
	var integrity string
	if err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil {
		return fail(err)
	}
	if integrity != "ok" {
		return fail(ErrInvalid)
	}
	s := &Store{db}
	if _, err = s.current(context.Background(), db); err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) current(ctx context.Context, q queryer) (checkpoint.Record, error) {
	var r checkpoint.Record
	var epoch, revision, digest []byte
	var count int
	err := q.QueryRowContext(ctx, `SELECT node,epoch,revision,digest,(SELECT count(*) FROM checkpoint) FROM checkpoint WHERE id=1`).Scan(&r.Node, &epoch, &revision, &digest, &count)
	if err != nil {
		return r, err
	}
	if count != 1 || len(epoch) != 8 || len(revision) != 8 || len(digest) != 32 {
		return r, ErrInvalid
	}
	r.Epoch = binary.BigEndian.Uint64(epoch)
	r.Revision = binary.BigEndian.Uint64(revision)
	copy(r.Digest[:], digest)
	if !valid(r) {
		return r, ErrInvalid
	}
	return r, nil
}
func (s *Store) Read(ctx context.Context, node string, epoch uint64, c checkpoint.Challenge) (checkpoint.Observation, error) {
	r, err := s.current(ctx, s.db)
	if err != nil {
		return checkpoint.Observation{}, err
	}
	if r.Node != node || r.Epoch != epoch {
		return checkpoint.Observation{}, ErrInvalid
	}
	return checkpoint.Observation{Record: r, Challenge: c}, nil
}

// CompareAndSwap compares the complete previous record. A successful exact
// retry returns the current next record; conflicts return the current record.
// Errors, including commit errors, may mean the write occurred.
func (s *Store) CompareAndSwap(ctx context.Context, prev, next checkpoint.Record, c checkpoint.Challenge) (observation checkpoint.Observation, result error) {
	if !valid(prev) || !valid(next) || prev.Node != next.Node || prev.Epoch != next.Epoch || prev.Revision == math.MaxUint64 || next.Revision != prev.Revision+1 {
		return checkpoint.Observation{}, ErrInvalid
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return checkpoint.Observation{}, err
	}
	defer conn.Close()
	// A failed COMMIT can leave SQLite's transaction active. Keep exclusive
	// ownership until rollback succeeds; never return a dirty connection.
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		conn.Raw(func(any) error { return driver.ErrBadConn })
		return checkpoint.Observation{}, err
	}
	committed := false
	defer func() {
		if !committed {
			if _, rollbackErr := conn.ExecContext(context.Background(), `ROLLBACK`); rollbackErr != nil {
				conn.Raw(func(any) error { return driver.ErrBadConn })
				result = errors.Join(result, fmt.Errorf("checkpoint rollback: %w", rollbackErr))
			}
		}
	}()
	r, err := s.current(ctx, conn)
	if err != nil {
		return checkpoint.Observation{}, err
	}
	if r.Node != prev.Node || r.Epoch != prev.Epoch {
		return checkpoint.Observation{}, ErrInvalid
	}
	if r == prev {
		_, err = conn.ExecContext(ctx, `UPDATE checkpoint SET node=?,epoch=?,revision=?,digest=? WHERE id=1`, next.Node, number(next.Epoch), number(next.Revision), next.Digest[:])
		if err != nil {
			return checkpoint.Observation{}, err
		}
		r, err = s.current(ctx, conn)
		if err != nil {
			return checkpoint.Observation{}, err
		}
		if r != next {
			return checkpoint.Observation{}, ErrInvalid
		}
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return checkpoint.Observation{}, err
	}
	committed = true
	return checkpoint.Observation{Record: r, Challenge: c}, nil
}
