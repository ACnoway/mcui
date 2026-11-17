package taskdispatch

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskauth"
)

// Record is the durable operator-facing view of a task. Raw contains the
// signed envelope; callers must authorize access before returning it.
type Record struct {
	TaskID        string
	NodeID        string
	Sequence      int64
	Raw           []byte
	Active        bool
	LeaseDeadline time.Time
	Acks          []Ack
}

type taskEnvelopeV2 struct {
	TaskID   string `json:"task_id"`
	NodeID   string `json:"node_id"`
	Sequence int64  `json:"sequence"`
	KeyID    string `json:"signing_key_id"`
}

// Issue allocates the next per-node sequence and stores one fully signed task
// atomically. build is called while the per-database write transaction is held
// so concurrent issuers cannot reserve the same sequence or leave a gap.
// Existing task IDs are returned idempotently; the caller must compare the
// stored intent with the retry request before acknowledging the retry.
func (s *Store) Issue(nodeID, taskID, keyID string, publicKey ed25519.PublicKey, build func(sequence int64) ([]byte, error)) (Delivery, error) {
	var zero Delivery
	if s == nil || s.db == nil || nodeID == "" || taskID == "" || keyID == "" || len(publicKey) != ed25519.PublicKeySize || build == nil {
		return zero, fmt.Errorf("%w: invalid issue arguments", ErrInvalid)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()

	var existing Delivery
	var existingKey string
	err = tx.QueryRow(`SELECT task_id,node_id,sequence,raw,key_id FROM tasks WHERE task_id=?`, taskID).Scan(&existing.TaskID, &existing.NodeID, &existing.Sequence, &existing.Raw, &existingKey)
	if err == nil {
		if existing.NodeID != nodeID || existingKey != keyID {
			return zero, ErrConflict
		}
		if err = tx.Commit(); err != nil {
			return zero, err
		}
		existing.Raw = append([]byte(nil), existing.Raw...)
		existing.LeaseID, existing.Deadline = "", time.Time{}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	var activeCount int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM tasks WHERE node_id=? AND active=1`, nodeID).Scan(&activeCount); err != nil {
		return zero, err
	}
	if activeCount != 0 {
		return zero, ErrConflict
	}
	var last int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM tasks WHERE node_id=?`, nodeID).Scan(&last); err != nil {
		return zero, err
	}
	if last >= MaxSequence {
		return zero, ErrSequence
	}
	sequence := last + 1
	raw, err := build(sequence)
	if err != nil {
		return zero, err
	}
	if _, err = protocol.CanonicalV2TaskBytes(raw); err != nil {
		return zero, fmt.Errorf("%w: signed task schema: %v", ErrInvalid, err)
	}
	var body taskEnvelopeV2
	if err = json.Unmarshal(raw, &body); err != nil {
		return zero, fmt.Errorf("%w: signed task fields: %v", ErrInvalid, err)
	}
	if body.NodeID != nodeID || body.TaskID != taskID || body.Sequence != sequence || body.KeyID != keyID {
		return zero, ErrIdentity
	}
	if err = protocol.VerifyV2Task(raw, publicKey); err != nil {
		return zero, fmt.Errorf("%w: task signature: %v", ErrInvalid, err)
	}
	if _, err = tx.Exec(`INSERT INTO tasks(task_id,node_id,sequence,raw,key_id,active) VALUES(?,?,?,?,?,1)`, taskID, nodeID, sequence, raw, keyID); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return Delivery{TaskID: taskID, NodeID: nodeID, Sequence: sequence, Raw: append([]byte(nil), raw...)}, nil
}

// GetRecord returns a task and its ordered ACK history. It does not authorize
// the caller; handlers must verify administrator scope before using it.
func (s *Store) GetRecord(taskID string) (Record, error) {
	var out Record
	if s == nil || s.db == nil || taskID == "" {
		return out, ErrInvalid
	}
	var active int
	var lease sql.NullInt64
	err := s.db.QueryRow(`SELECT task_id,node_id,sequence,raw,active,lease_deadline FROM tasks WHERE task_id=?`, taskID).Scan(&out.TaskID, &out.NodeID, &out.Sequence, &out.Raw, &active, &lease)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.Active = active == 1
	if lease.Valid {
		out.LeaseDeadline = time.Unix(0, lease.Int64).UTC()
	}
	out.Raw = append([]byte(nil), out.Raw...)
	out.Acks, err = s.readAcks(taskID)
	return out, err
}

// ListRecords returns the newest task records for one node, in descending
// sequence order. A zero limit selects the bounded default of 100.
func (s *Store) ListRecords(nodeID string, limit int) ([]Record, error) {
	if s == nil || s.db == nil || nodeID == "" {
		return nil, ErrInvalid
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT task_id,node_id,sequence,raw,active,lease_deadline FROM tasks WHERE node_id=? ORDER BY sequence DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	var out []Record
	for rows.Next() {
		var r Record
		var active int
		var lease sql.NullInt64
		if err = rows.Scan(&r.TaskID, &r.NodeID, &r.Sequence, &r.Raw, &active, &lease); err != nil {
			return nil, err
		}
		r.Active = active == 1
		if lease.Valid {
			r.LeaseDeadline = time.Unix(0, lease.Int64).UTC()
		}
		r.Raw = append([]byte(nil), r.Raw...)
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Acks, err = s.readAcks(out[i].TaskID)
		if err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []Record{}
	}
	return out, nil
}

func (s *Store) readAcks(taskID string) ([]Ack, error) {
	rows, err := s.db.Query(`SELECT node_id,task_id,sequence,status_version,status,result FROM acks WHERE task_id=? ORDER BY status_version`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ack
	for rows.Next() {
		var ack Ack
		if err = rows.Scan(&ack.NodeID, &ack.TaskID, &ack.Sequence, &ack.StatusVersion, &ack.Status, &ack.Result); err != nil {
			return nil, err
		}
		ack.Result = append([]byte(nil), ack.Result...)
		out = append(out, ack)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Ack{}
	}
	return out, nil
}

// ValidateLease is the independent Master-side freshness checkpoint used by a
// status-only Helper. It accepts only the exact currently leased envelope and
// confirms that every earlier per-node task is terminal before authorizing the
// read. previousSequence is therefore safe for the Helper to reconcile into
// its local ledger after a restart or expired status query.
func (s *Store) ValidateLease(nodeID, taskID string, sequence int64, leaseID string, raw []byte, now time.Time, keyID string, publicKey ed25519.PublicKey) (previousSequence int64, err error) {
	if s == nil || s.db == nil || nodeID == "" || taskID == "" || sequence < 1 || leaseID == "" || len(raw) == 0 || now.IsZero() || keyID == "" || len(publicKey) != ed25519.PublicKeySize {
		return 0, ErrInvalid
	}
	verified, err := taskauth.Verify(raw, taskauth.Trust{
		NodeID: nodeID,
		Keys:   map[string]taskauth.Key{keyID: {PublicKey: append(ed25519.PublicKey(nil), publicKey...), Active: true, Purpose: taskauth.PurposeTask}},
		Now:    now,
	})
	if err != nil || verified.TaskID != taskID || int64(verified.Sequence) != sequence || verified.KeyID != keyID {
		return 0, ErrIdentity
	}
	var storedNode, storedKey string
	var storedRaw []byte
	var active int
	var storedLease sql.NullString
	var deadline sql.NullInt64
	err = s.db.QueryRow(`SELECT node_id,raw,key_id,active,lease_id,lease_deadline FROM tasks WHERE task_id=?`, taskID).Scan(&storedNode, &storedRaw, &storedKey, &active, &storedLease, &deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if storedNode != nodeID || storedKey != keyID || active != 1 || !storedLease.Valid || storedLease.String != leaseID || !deadline.Valid || deadline.Int64 <= now.UnixNano() || !bytes.Equal(storedRaw, raw) {
		return 0, ErrLeaseActive
	}
	var count, activePrevious int64
	if err = s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(active),0) FROM tasks WHERE node_id=? AND sequence<?`, nodeID, sequence).Scan(&count, &activePrevious); err != nil {
		return 0, err
	}
	if count != sequence-1 || activePrevious != 0 {
		return 0, ErrSequence
	}
	return sequence - 1, nil
}
