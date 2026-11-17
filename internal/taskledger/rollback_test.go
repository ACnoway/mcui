package taskledger

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

var errInjectedRollback = errors.New("injected rollback failure")
var errInjectedBegin = errors.New("injected begin failure")

type rollbackFailConnector struct {
	path      string
	fail      atomic.Bool
	failBegin atomic.Bool
}

func (c *rollbackFailConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.path)
	if err != nil {
		return nil, err
	}
	return &rollbackFailConn{Conn: conn, connector: c}, nil
}
func (c *rollbackFailConnector) Driver() driver.Driver { return &sqlite.Driver{} }

type rollbackFailConn struct {
	driver.Conn
	connector *rollbackFailConnector
}

func (c *rollbackFailConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(query))
	if trimmed == "BEGIN IMMEDIATE" && c.connector.failBegin.CompareAndSwap(true, false) {
		// Simulate BEGIN taking effect before its error reaches the caller.
		if _, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args); err != nil {
			return nil, err
		}
		return nil, errInjectedBegin
	}
	if trimmed == "ROLLBACK" && c.connector.fail.CompareAndSwap(true, false) {
		return nil, errInjectedRollback
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}
func (c *rollbackFailConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func TestRollbackFailureDiscardsDirtyConnection(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.db.Close(); err != nil {
		t.Fatal(err)
	}
	connector := &rollbackFailConnector{path: path}
	l.db = sql.OpenDB(connector)
	l.db.SetMaxOpenConns(1)
	defer l.Close()

	primary := errors.New("operation failed")
	connector.fail.Store(true)
	err = l.write(func(c *sql.Conn) error {
		if _, err := c.ExecContext(context.Background(), `UPDATE metadata SET next_seq=42 WHERE id=1`); err != nil {
			return err
		}
		return primary
	})
	if !errors.Is(err, primary) || !errors.Is(err, errInjectedRollback) {
		t.Errorf("expected original and rollback errors, got %v", err)
	}
	if idle := l.db.Stats().Idle; idle != 0 {
		t.Errorf("dirty connection returned to pool: %d idle", idle)
	}
	var got int
	if err := l.db.QueryRow(`SELECT next_seq FROM metadata WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("uncommitted value exposed after failed rollback: %d", got)
	}
}

// BEGIN errors may report an uncertain transaction state, so never pool that connection.
func TestFailedBeginDiscardsConnection(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.db")
	l, err := Initialize(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.db.Close(); err != nil {
		t.Fatal(err)
	}
	connector := &rollbackFailConnector{path: path}
	l.db = sql.OpenDB(connector)
	l.db.SetMaxOpenConns(1)
	defer l.Close()
	connector.failBegin.Store(true)
	if _, err := l.Next(); !errors.Is(err, errInjectedBegin) {
		t.Fatalf("begin error: %v", err)
	}
	if idle := l.db.Stats().Idle; idle != 0 {
		t.Fatalf("failed BEGIN connection pooled: %d idle", idle)
	}
	if next, err := l.Next(); err != nil || next != 1 {
		t.Fatalf("next after failure = %d, %v", next, err)
	}
}

// A separate reader keeps a shared lock until COMMIT, which must roll back on SQLITE_BUSY.
func TestBusyCommitDoesNotExposeUncommittedState(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict=%t", conflict), func(t *testing.T) {
			path := filepath.Join(privateDir(t), "ledger.db")
			l, err := Initialize(path)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			if _, err := l.db.Exec("PRAGMA busy_timeout=20"); err != nil {
				t.Fatal(err)
			}
			reader, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			tx, err := reader.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			var n int
			if err := tx.QueryRow("SELECT next_seq FROM metadata WHERE id=1").Scan(&n); err != nil {
				t.Fatal(err)
			}
			err = l.write(func(c *sql.Conn) error {
				if _, err := c.ExecContext(context.Background(), "UPDATE metadata SET next_seq=42 WHERE id=1"); err != nil {
					return err
				}
				if conflict {
					return ErrConflict
				}
				return nil
			})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "busy") {
				t.Fatalf("expected SQLITE_BUSY commit, got %v", err)
			}
			if err := l.db.QueryRow("SELECT next_seq FROM metadata WHERE id=1").Scan(&n); err != nil || n != 1 {
				t.Fatalf("read after failed commit: %d, %v", n, err)
			}
			var quarantined int
			if err := l.db.QueryRow("SELECT count(*) FROM quarantine").Scan(&quarantined); err != nil || quarantined != 0 {
				t.Fatalf("quarantine after failed commit: %d, %v", quarantined, err)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if next, err := l.Next(); err != nil || next != 1 {
				t.Fatalf("next after failed commit: %d, %v", next, err)
			}
		})
	}
}
