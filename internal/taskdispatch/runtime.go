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
	"github.com/ACnoway/mcui/internal/taskcontrol"
)

// Record is the durable operator-facing view of a task. Raw contains the
// signed envelope; callers must authorize access before returning it.
type Record struct {
	TaskID        string
	NodeID        string
	Sequence      int64
	Raw           []byte
	ControlKind   string
	ControlRaw    []byte
	Active        bool
	LeaseDeadline time.Time
	Acks          []Ack
}

type TaskReference struct {
	TaskID      string
	NodeID      string
	Sequence    int64
	Raw         []byte
	ControlKind string
	ControlRaw  []byte
	Active      bool
	LastStatus  string
}

type taskEnvelopeV2 struct {
	TaskID    string `json:"task_id"`
	NodeID    string `json:"node_id"`
	Sequence  int64  `json:"sequence"`
	Operation string `json:"operation"`
	KeyID     string `json:"signing_key_id"`
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
	if body.NodeID != nodeID || body.TaskID != taskID || body.Sequence != sequence || body.Operation != "core.status" || body.KeyID != keyID {
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
	var controlKind sql.NullString
	err := s.db.QueryRow(`SELECT t.task_id,t.node_id,t.sequence,t.raw,c.kind,c.raw,t.active,t.lease_deadline FROM tasks t LEFT JOIN task_controls c ON c.task_id=t.task_id WHERE t.task_id=?`, taskID).Scan(&out.TaskID, &out.NodeID, &out.Sequence, &out.Raw, &controlKind, &out.ControlRaw, &active, &lease)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.Active = active == 1
	if controlKind.Valid {
		out.ControlKind = controlKind.String
	}
	if lease.Valid {
		out.LeaseDeadline = time.Unix(0, lease.Int64).UTC()
	}
	out.Raw = append([]byte(nil), out.Raw...)
	out.ControlRaw = append([]byte(nil), out.ControlRaw...)
	out.Acks, err = s.readAcks(taskID)
	return out, err
}

// ListTaskReferences returns immutable task identities for cross-database
// issuance/audit reconciliation. It intentionally omits ACK payloads.
func (s *Store) ListTaskReferences() ([]TaskReference, error) {
	if s == nil || s.db == nil {
		return nil, ErrInvalid
	}
	rows, err := s.db.Query(`SELECT t.task_id,t.node_id,t.sequence,t.raw,c.kind,c.raw,t.active,COALESCE((SELECT status FROM acks WHERE task_id=t.task_id ORDER BY status_version DESC LIMIT 1),'') FROM tasks t LEFT JOIN task_controls c ON c.task_id=t.task_id ORDER BY t.node_id,t.sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskReference
	for rows.Next() {
		var ref TaskReference
		var controlKind sql.NullString
		if err = rows.Scan(&ref.TaskID, &ref.NodeID, &ref.Sequence, &ref.Raw, &controlKind, &ref.ControlRaw, &ref.Active, &ref.LastStatus); err != nil {
			return nil, err
		}
		if controlKind.Valid {
			ref.ControlKind = controlKind.String
		}
		ref.Raw = bytes.Clone(ref.Raw)
		ref.ControlRaw = bytes.Clone(ref.ControlRaw)
		out = append(out, ref)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []TaskReference{}
	}
	return out, nil
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
	rows, err := s.db.Query(`SELECT t.task_id,t.node_id,t.sequence,t.raw,c.kind,c.raw,t.active,t.lease_deadline FROM tasks t LEFT JOIN task_controls c ON c.task_id=t.task_id WHERE t.node_id=? ORDER BY t.sequence DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	var out []Record
	for rows.Next() {
		var r Record
		var active int
		var lease sql.NullInt64
		var controlKind sql.NullString
		if err = rows.Scan(&r.TaskID, &r.NodeID, &r.Sequence, &r.Raw, &controlKind, &r.ControlRaw, &active, &lease); err != nil {
			return nil, err
		}
		if controlKind.Valid {
			r.ControlKind = controlKind.String
		}
		r.Active = active == 1
		if lease.Valid {
			r.LeaseDeadline = time.Unix(0, lease.Int64).UTC()
		}
		r.Raw = append([]byte(nil), r.Raw...)
		r.ControlRaw = append([]byte(nil), r.ControlRaw...)
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

// SetControl attaches one signed V1 cancel or skip control to an active,
// read-only status task. The control and lease invalidation commit together.
func (s *Store) SetControl(authenticatedNodeID, taskID string, kind protocol.Kind, raw []byte, now time.Time, keyID string, publicKey ed25519.PublicKey) error {
	if s == nil || s.db == nil || authenticatedNodeID == "" || taskID == "" || (kind != protocol.Cancel && kind != protocol.Skip) || len(raw) == 0 || len(raw) > 64*1024 || now.IsZero() || keyID == "" || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	verified, err := taskcontrol.Verify(kind, raw, taskcontrol.Trust{NodeID: authenticatedNodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
	if err != nil {
		return fmt.Errorf("%w: invalid signed task control: %v", ErrInvalid, err)
	}
	var task struct {
		TaskID    string    `json:"task_id"`
		NodeID    string    `json:"node_id"`
		Sequence  int64     `json:"sequence"`
		Operation string    `json:"operation"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	// The signed status task is loaded under the transaction below. Control
	// identity and time checks that depend on it are repeated against that row.
	if kind == protocol.Cancel && verified.TaskID == "" {
		return ErrIdentity
	}
	controlCopy := bytes.Clone(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var node, storedKey string
	var sequence int64
	var taskRaw []byte
	var active int
	var oldKind sql.NullString
	var oldRaw []byte
	err = tx.QueryRow(`SELECT node_id,sequence,raw,key_id,active FROM tasks WHERE task_id=?`, taskID).Scan(&node, &sequence, &taskRaw, &storedKey, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	err = tx.QueryRow(`SELECT kind,raw FROM task_controls WHERE task_id=?`, taskID).Scan(&oldKind, &oldRaw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if node != authenticatedNodeID || storedKey != keyID || active != 1 {
		return ErrIdentity
	}
	if _, err = protocol.CanonicalV2TaskBytes(taskRaw); err != nil || protocol.VerifyV2Task(taskRaw, publicKey) != nil || json.Unmarshal(taskRaw, &task) != nil || task.TaskID != taskID || task.NodeID != node || task.Sequence != sequence || task.Operation != "core.status" || task.ExpiresAt.IsZero() {
		return ErrIdentity
	}
	if int64(verified.Sequence) != sequence || verified.NodeID != node {
		return ErrIdentity
	}
	switch kind {
	case protocol.Cancel:
		if verified.TaskID != taskID || !now.Before(task.ExpiresAt) {
			return ErrConflict
		}
	case protocol.Skip:
		if verified.Reason != "EXPIRED" || now.Before(task.ExpiresAt) || verified.IssuedAt.Before(task.ExpiresAt) {
			return ErrConflict
		}
	}
	var started int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM acks WHERE task_id=? AND status IN ('RUNNING','VERIFYING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','NEEDS_RECONCILIATION','CANCELED','EXPIRED')`, taskID).Scan(&started); err != nil {
		return err
	}
	if started != 0 {
		return ErrConflict
	}
	if oldKind.Valid {
		if oldKind.String == string(kind) {
			oldControl, oldErr := taskcontrol.Verify(kind, oldRaw, taskcontrol.Trust{NodeID: authenticatedNodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
			if oldErr == nil {
				if oldControl.NodeID == verified.NodeID && oldControl.Sequence == verified.Sequence && oldControl.TaskID == verified.TaskID && oldControl.Reason == verified.Reason {
					return tx.Commit()
				}
				return ErrConflict
			}
			if !errors.Is(oldErr, taskcontrol.ErrTime) {
				return ErrConflict
			}
		} else if kind != protocol.Skip || oldKind.String != string(protocol.Cancel) || now.Before(task.ExpiresAt) {
			return ErrConflict
		}
	}
	if _, err = tx.Exec(`INSERT INTO task_controls(task_id,kind,raw) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET kind=excluded.kind,raw=excluded.raw`, taskID, string(kind), controlCopy); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tasks SET lease_id=NULL,lease_deadline=NULL WHERE task_id=? AND active=1`, taskID); err != nil {
		return err
	}
	return tx.Commit()
}

// VoidUnissued closes only a persisted status slot that has never been leased
// or acknowledged. The signed skip and slot closure commit together.
func (s *Store) VoidUnissued(nodeID, taskID string, raw []byte, now time.Time, keyID string, publicKey ed25519.PublicKey) error {
	if s == nil || s.db == nil || nodeID == "" || taskID == "" || len(raw) == 0 || len(raw) > 64*1024 || now.IsZero() || keyID == "" || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	control, err := taskcontrol.Verify(protocol.Skip, raw, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
	if err != nil || control.Reason != "VOID_UNISSUED" {
		return ErrIdentity
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storedNode, storedKey string
	var sequence int64
	var taskRaw []byte
	var active int
	var lease sql.NullString
	var deadline sql.NullInt64
	if err = tx.QueryRow(`SELECT node_id,sequence,raw,key_id,active,lease_id,lease_deadline FROM tasks WHERE task_id=?`, taskID).Scan(&storedNode, &sequence, &taskRaw, &storedKey, &active, &lease, &deadline); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var body taskEnvelopeV2
	if storedNode != nodeID || storedKey != keyID || active != 1 || lease.Valid || deadline.Valid || int64(control.Sequence) != sequence || protocol.VerifyV2Task(taskRaw, publicKey) != nil || json.Unmarshal(taskRaw, &body) != nil || body.TaskID != taskID || body.NodeID != nodeID || body.Sequence != sequence || body.Operation != "core.status" || body.KeyID != keyID {
		return ErrConflict
	}
	var acks, controls int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM acks WHERE task_id=?`, taskID).Scan(&acks); err != nil {
		return err
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM task_controls WHERE task_id=?`, taskID).Scan(&controls); err != nil {
		return err
	}
	if acks != 0 || controls != 0 {
		return ErrConflict
	}
	if _, err = tx.Exec(`INSERT INTO task_controls(task_id,kind,raw) VALUES(?,?,?)`, taskID, string(protocol.Skip), bytes.Clone(raw)); err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE tasks SET active=0,lease_id=NULL,lease_deadline=NULL WHERE task_id=? AND active=1`, taskID); err != nil {
		return err
	}
	return tx.Commit()
}

// AcknowledgeVoid records the mTLS-authenticated Agent receipt of a
// VOID_UNISSUED slot. It re-verifies both the persisted skip and its task.
func (s *Store) AcknowledgeVoid(nodeID string, ack Ack, now time.Time, keyID string, publicKey ed25519.PublicKey) error {
	if s == nil || s.db == nil || nodeID == "" || ack.NodeID != nodeID || ack.TaskID == "" || ack.Sequence < 1 || ack.StatusVersion != 1 || ack.Status != "CANCELED" || now.IsZero() || keyID == "" || len(publicKey) != ed25519.PublicKeySize || len(ack.Result) > MaxResultBytes || !json.Valid(ack.Result) {
		return ErrInvalid
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var taskNode, storedKey string
	var sequence int64
	var taskRaw, skipRaw []byte
	var active int
	var lease sql.NullString
	var deadline sql.NullInt64
	err = tx.QueryRow(`SELECT t.node_id,t.sequence,t.raw,t.key_id,t.active,t.lease_id,t.lease_deadline,c.raw FROM tasks t JOIN task_controls c ON c.task_id=t.task_id WHERE t.task_id=? AND c.kind='skip'`, ack.TaskID).Scan(&taskNode, &sequence, &taskRaw, &storedKey, &active, &lease, &deadline, &skipRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	control, controlErr := taskcontrol.Verify(protocol.Skip, skipRaw, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
	var body taskEnvelopeV2
	if taskNode != nodeID || storedKey != keyID || sequence != ack.Sequence || active != 0 || lease.Valid || deadline.Valid || protocol.VerifyV2Task(taskRaw, publicKey) != nil || json.Unmarshal(taskRaw, &body) != nil || body.TaskID != ack.TaskID || body.NodeID != nodeID || body.Sequence != sequence || body.Operation != "core.status" || body.KeyID != keyID || controlErr != nil || control.Reason != "VOID_UNISSUED" || int64(control.Sequence) != sequence {
		return ErrIdentity
	}
	var count int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM acks WHERE task_id=?`, ack.TaskID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrConflict
	}
	if _, err = tx.Exec(`INSERT INTO acks(task_id,status_version,node_id,sequence,status,result) VALUES(?,?,?,?,?,?)`, ack.TaskID, 1, nodeID, sequence, ack.Status, bytes.Clone(ack.Result)); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM task_controls WHERE task_id=?`, ack.TaskID); err != nil {
		return err
	}
	return tx.Commit()
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
