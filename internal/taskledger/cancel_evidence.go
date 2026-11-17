package taskledger

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
)

// AcceptCancel records the exact cancellation envelope. The caller MUST first
// authenticate it and validate its V1 kind, target, key authorization, validity,
// and that seq and id are exactly those in the authenticated bytes. This method
// does not verify signatures, clocks, policy or rollback. The bytes are compared
// exactly, including the signature; a different envelope is a conflict. Senders
// must deliver the same immutable envelope bytes on every retry. Node scope is
// established externally by the caller; this ledger does not bind a node.
func (l *Ledger) AcceptCancel(seq int64, id string, envelope []byte) error {
	return l.AcceptCancelValidated(seq, id, envelope, nil)
}

// AcceptCancelValidated invokes verify inside the SQLite write transaction,
// after acquiring the write lock and immediately before inspecting sequence
// and task state. The callback must authenticate the exact immutable envelope,
// including node, key purpose, validity, sequence, and task ID.
func (l *Ledger) AcceptCancelValidated(seq int64, id string, envelope []byte, verify func() error) error {
	if seq < 1 || id == "" || len(envelope) == 0 || len(envelope) > 65536 {
		return errors.New("invalid cancellation")
	}
	snapshot := append([]byte(nil), envelope...)
	return l.write(func(c *sql.Conn) error {
		if verify != nil {
			if err := verify(); err != nil {
				return err
			}
		}
		ctx := context.Background()
		n, err := next(c)
		if err != nil {
			return err
		}
		var oldID string
		var old []byte
		err = c.QueryRowContext(ctx, `SELECT id,envelope FROM cancellations WHERE seq=?`, seq).Scan(&oldID, &old)
		if err == nil {
			if oldID != id || !bytes.Equal(old, snapshot) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var used int64
		err = c.QueryRowContext(ctx, `SELECT seq FROM cancellations WHERE id=?`, id).Scan(&used)
		if err == nil {
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		err = c.QueryRowContext(ctx, `SELECT seq FROM tasks WHERE id=?`, id).Scan(&used)
		if err == nil && used != seq {
			return ErrConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		task, err := readTask(c, seq)
		if err == nil {
			if task.ID != id {
				return ErrConflict
			}
			if task.State != Pending {
				return ErrTooLate
			}
		} else if !errors.Is(err, ErrNotFound) {
			return err
		} else if seq < n {
			return ErrConflict
		}
		_, err = c.ExecContext(ctx, `INSERT INTO cancellations(seq,id,envelope) VALUES(?,?,?)`, seq, id, snapshot)
		if err != nil {
			return err
		}
		if task.State == Pending {
			if _, err = c.ExecContext(ctx, `UPDATE tasks SET state=? WHERE seq=?`, Canceled, seq); err != nil {
				return err
			}
			return advance(c)
		}
		return nil
	})
}

// GetCancel returns a cancellation's task ID and exact signed envelope by sequence,
// including for a future tombstone with no task yet. The returned bytes are owned
// by the caller. Authentication and node scoping remain the caller's responsibility.
func (l *Ledger) GetCancel(seq int64) (id string, envelope []byte, err error) {
	err = l.write(func(c *sql.Conn) error {
		e := c.QueryRowContext(context.Background(), `SELECT id,envelope FROM cancellations WHERE seq=?`, seq).Scan(&id, &envelope)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrNotFound
		}
		return e
	})
	return
}
