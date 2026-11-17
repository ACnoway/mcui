package taskledger

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

var (
	ErrGap         = errors.New("sequence gap")
	ErrConflict    = errors.New("task conflict")
	ErrNotFound    = errors.New("task not found")
	ErrState       = errors.New("invalid task state")
	ErrNotYet      = errors.New("task not yet valid")
	ErrTooLate     = errors.New("cancel too late")
	ErrQuarantined = errors.New("ledger quarantined")
)

type State string

const (
	Pending        State = "PENDING"
	Running        State = "RUNNING"
	Expired        State = "EXPIRED"
	Canceled       State = "CANCELED"
	Succeeded      State = "SUCCEEDED"
	Failed         State = "FAILED"
	Reconciliation State = "NEEDS_RECONCILIATION"
)

type Task struct {
	ID                   string
	Sequence             int64
	Envelope             []byte
	NotBefore, ExpiresAt time.Time
	State                State
	Result               []byte
}

// write acquires the SQLite write lock before reading, across connections and processes.
func (l *Ledger) write(fn func(*sql.Conn) error) (err error) {
	ctx := context.Background()
	c, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		// A failed BEGIN can leave the transaction state uncertain.
		_ = c.Raw(func(any) error { return driver.ErrBadConn })
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if _, rollbackErr := c.ExecContext(context.Background(), "ROLLBACK"); rollbackErr != nil {
				_ = c.Raw(func(any) error { return driver.ErrBadConn })
				err = errors.Join(err, fmt.Errorf("ledger rollback: %w", rollbackErr))
			}
		}
	}()
	var quarantined int
	if err = c.QueryRowContext(ctx, `SELECT COUNT(*) FROM quarantine`).Scan(&quarantined); err != nil {
		return err
	}
	if quarantined != 0 {
		return ErrQuarantined
	}
	if err = fn(c); err != nil {
		if !errors.Is(err, ErrConflict) {
			return err
		}
		if _, e := c.ExecContext(ctx, `INSERT INTO quarantine(id,reason) VALUES(1,?)`, err.Error()); e != nil {
			return e
		}
		if _, e := c.ExecContext(ctx, "COMMIT"); e != nil {
			return e
		}
		committed = true
		return ErrConflict
	}
	_, err = c.ExecContext(ctx, "COMMIT")
	committed = err == nil
	return err
}
func readTask(c *sql.Conn, seq int64) (Task, error) {
	var t Task
	var nb, ex int64
	err := c.QueryRowContext(context.Background(), `SELECT seq,id,envelope,not_before,expires,state,result FROM tasks WHERE seq=?`, seq).Scan(&t.Sequence, &t.ID, &t.Envelope, &nb, &ex, &t.State, &t.Result)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	t.NotBefore = time.Unix(0, nb).UTC()
	t.ExpiresAt = time.Unix(0, ex).UTC()
	return t, err
}
func next(c *sql.Conn) (n int64, err error) {
	err = c.QueryRowContext(context.Background(), `SELECT next_seq FROM metadata WHERE id=1`).Scan(&n)
	return
}
func advance(c *sql.Conn) error {
	r, err := c.ExecContext(context.Background(), `UPDATE metadata SET next_seq=next_seq+1 WHERE id=1 AND next_seq<9223372036854775807`)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("sequence overflow or missing metadata")
	}
	return nil
}
func (l *Ledger) Next() (int64, error) {
	var n int64
	err := l.write(func(c *sql.Conn) error { var e error; n, e = next(c); return e })
	return n, err
}

// Accept requires prior authentication, target and policy validation by the caller.
// Envelope is the exact signed delivery bytes and is compared without normalization.
// Senders must deliver immutable byte-identical envelopes on every retry.
func (l *Ledger) Accept(t Task, now time.Time) (out Task, err error) {
	if t.ID == "" || t.Sequence < 1 || len(t.Envelope) == 0 || len(t.Envelope) > 65536 || t.NotBefore.IsZero() || t.ExpiresAt.IsZero() || !t.NotBefore.Before(t.ExpiresAt) || !time.Unix(0, t.NotBefore.UnixNano()).Equal(t.NotBefore) || !time.Unix(0, t.ExpiresAt.UnixNano()).Equal(t.ExpiresAt) {
		return out, errors.New("invalid task")
	}
	err = l.write(func(c *sql.Conn) error {
		n, e := next(c)
		if e != nil {
			return e
		}
		if t.Sequence > n {
			return ErrGap
		}
		existing, e := readTask(c, t.Sequence)
		if e == nil {
			if existing.ID != t.ID || !bytes.Equal(existing.Envelope, t.Envelope) || !existing.NotBefore.Equal(t.NotBefore) || !existing.ExpiresAt.Equal(t.ExpiresAt) {
				return ErrConflict
			}
			out = existing
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		if t.Sequence < n {
			return ErrConflict
		}
		var used int64
		e = c.QueryRowContext(context.Background(), `SELECT seq FROM tasks WHERE id=?`, t.ID).Scan(&used)
		if e == nil {
			return ErrConflict
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var tombSeq int64
		e = c.QueryRowContext(context.Background(), `SELECT seq FROM cancellations WHERE id=?`, t.ID).Scan(&tombSeq)
		if e == nil && tombSeq != t.Sequence {
			return ErrConflict
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		var cid string
		e = c.QueryRowContext(context.Background(), `SELECT id FROM cancellations WHERE seq=?`, t.Sequence).Scan(&cid)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil && cid != t.ID {
			return ErrConflict
		}
		state := Pending
		if e == nil {
			state = Canceled
		} else if !now.Before(t.ExpiresAt) {
			state = Expired
		}
		_, e = c.ExecContext(context.Background(), `INSERT INTO tasks(seq,id,envelope,not_before,expires,state) VALUES(?,?,?,?,?,?)`, t.Sequence, t.ID, t.Envelope, t.NotBefore.UnixNano(), t.ExpiresAt.UnixNano(), state)
		if e != nil {
			return fmt.Errorf("insert task: %w", e)
		}
		if state != Pending {
			if e = advance(c); e != nil {
				return e
			}
		}
		out, e = readTask(c, t.Sequence)
		return e
	})
	return
}

// Start persists RUNNING before the caller performs any work.
func (l *Ledger) Start(seq int64, now time.Time) (out Task, err error) {
	err = l.write(func(c *sql.Conn) error {
		t, e := readTask(c, seq)
		if e != nil {
			return e
		}
		if t.State != Pending {
			return ErrState
		}
		if !now.Before(t.ExpiresAt) {
			t.State = Expired
		} else if now.Before(t.NotBefore) {
			return ErrNotYet
		} else {
			t.State = Running
		}
		_, e = c.ExecContext(context.Background(), `UPDATE tasks SET state=? WHERE seq=?`, t.State, seq)
		if e != nil {
			return e
		}
		if t.State == Expired {
			if e = advance(c); e != nil {
				return e
			}
		}
		out = t
		return nil
	})
	return
}

// Get returns the immutable delivery and current durable state.
func (l *Ledger) Get(seq int64) (out Task, err error) {
	err = l.write(func(c *sql.Conn) error { var e error; out, e = readTask(c, seq); return e })
	return
}

// Finish records the result and advances the slot atomically. It cannot resolve
// uncertain outcomes after restart; that requires an external recovery protocol.
func (l *Ledger) Finish(seq int64, state State, result []byte) error {
	if state != Succeeded && state != Failed {
		return ErrState
	}
	if len(result) > 65536 {
		return errors.New("result too large")
	}
	return l.write(func(c *sql.Conn) error {
		t, e := readTask(c, seq)
		if e != nil {
			return e
		}
		if t.State == state && bytes.Equal(t.Result, result) {
			return nil
		}
		if t.State != Running {
			return ErrState
		}
		_, e = c.ExecContext(context.Background(), `UPDATE tasks SET state=?, result=? WHERE seq=?`, state, result, seq)
		if e != nil {
			return e
		}
		return advance(c)
	})
}
