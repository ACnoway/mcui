// Package taskdispatch is an isolated, storage-only Master task delivery
// boundary. It authenticates no transport and executes no task. Callers must
// supply an already authenticated node identity, trusted task verification key,
// and current time explicitly.
package taskdispatch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
	_ "modernc.org/sqlite"
)

const (
	MaxSequence    int64 = 9007199254740991
	LeasePeriod          = 60 * time.Second
	MaxResultBytes       = 4096
	// MaxAckVersions bounds the durable storage used by one task's ACKs.
	MaxAckVersions int64 = 9
)

var (
	ErrConflict    = errors.New("task delivery conflict")
	ErrNotFound    = errors.New("task delivery not found")
	ErrLeaseActive = errors.New("task delivery lease is active")
	ErrIdentity    = errors.New("task delivery identity mismatch")
	ErrSequence    = errors.New("task delivery sequence mismatch")
	ErrInvalid     = errors.New("invalid task delivery input")
)

// Delivery contains the original signed bytes. Raw is copied on return and is
// never interpreted as executable input by this package.
type Delivery struct {
	NodeID            string
	TaskID            string
	Sequence          int64
	Raw               []byte
	LeaseID           string
	Deadline          time.Time
	LastStatusVersion int64
}

// Ack is a persisted observation from an externally authenticated node. Result
// is opaque, limited to MaxResultBytes, and is not sanitized for secrets.
type Ack struct {
	NodeID        string
	TaskID        string
	Sequence      int64
	StatusVersion int64
	Status        string
	Result        []byte
}

type taskEnvelope struct {
	TaskID    string `json:"task_id"`
	NodeID    string `json:"node_id"`
	Sequence  int64  `json:"sequence"`
	KeyID     string `json:"signing_key_id"`
	Operation string `json:"operation"`
}

type Store struct{ db *sql.DB }

var allowedStatuses = map[string]bool{
	"QUEUED": true, "LEASED": true, "ACK_ACCEPTED": true, "RUNNING": true,
	"VERIFYING": true, "SUCCEEDED": true, "FAILED": true, "ROLLING_BACK": true,
	"ROLLED_BACK": true, "EXPIRED": true, "CANCELED": true,
	"NEEDS_RECONCILIATION": true,
}

var terminalStatuses = map[string]bool{
	"SUCCEEDED": true, "ROLLED_BACK": true, "EXPIRED": true,
	"CANCELED": true,
}

// Init creates a new private database and fails if path already exists. A
// partially initialized file is removed on initialization failure.
func Init(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty database path", ErrInvalid)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(path)
		}
	}()

	s, err := connect(path)
	if err != nil {
		return nil, err
	}
	if err = createSchema(s.db); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err = validateSchema(s.db); err != nil {
		_ = s.Close()
		return nil, err
	}
	cleanup = false
	return s, nil
}

// Open opens only an already initialized database and validates its schema and
// durable invariants. It never creates or repairs a database.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty database path", ErrInvalid)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("invalid task delivery database: not a regular file")
	}
	s, err := connect(path)
	if err != nil {
		return nil, err
	}
	if err = validateSchema(s.db); err != nil {
		_ = s.Close()
		return nil, err
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
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	// Never pool a connection: a failed SQLite COMMIT can leave a transaction open.
	db.SetMaxIdleConns(0)
	if err = db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE metadata (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 version INTEGER NOT NULL CHECK(version=1)
);
INSERT INTO metadata(singleton,version) VALUES(1,1);
CREATE TABLE tasks (
 task_id TEXT PRIMARY KEY,
 node_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence > 0 AND sequence <= 9007199254740991),
 raw BLOB NOT NULL,
 key_id TEXT NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1)),
 lease_id TEXT,
 lease_deadline INTEGER,
 UNIQUE(node_id,sequence)
);
CREATE UNIQUE INDEX one_active_per_node ON tasks(node_id) WHERE active=1;
CREATE TABLE acks (
 task_id TEXT NOT NULL REFERENCES tasks(task_id),
 status_version INTEGER NOT NULL CHECK(status_version > 0),
 node_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence > 0),
 status TEXT NOT NULL,
 result BLOB NOT NULL,
 PRIMARY KEY(task_id,status_version)
);
CREATE INDEX acks_by_task ON acks(task_id,status_version);
`)
	return err
}

func validateSchema(db *sql.DB) error {
	// Compare every schema object, including triggers, against a freshly created
	// trusted schema. Names alone do not establish constraints or uniqueness.
	expected, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer expected.Close()
	if err = createSchema(expected); err != nil {
		return err
	}
	schema := func(d *sql.DB) (map[string]string, error) {
		rows, e := d.Query(`SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name`)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var typ, name, table, ddl string
			if e = rows.Scan(&typ, &name, &table, &ddl); e != nil {
				return nil, e
			}
			out[typ+"\x00"+name] = table + "\x00" + ddl
		}
		return out, rows.Err()
	}
	want, err := schema(expected)
	if err != nil {
		return err
	}
	got, err := schema(db)
	if err != nil {
		return err
	}
	if len(want) != len(got) {
		return errors.New("invalid task delivery database schema objects")
	}
	for k, v := range want {
		if got[k] != v {
			return fmt.Errorf("invalid task delivery schema object %q", k)
		}
	}
	var journal string
	if err = db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		return err
	}
	if journal != "delete" && journal != "truncate" && journal != "persist" && journal != "wal" {
		return fmt.Errorf("unsafe task delivery journal mode: %s", journal)
	}
	var integrity string
	if err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("invalid task delivery integrity: %s: %v", integrity, err)
	}
	fk, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	hasFK := fk.Next()
	fkErr := fk.Err()
	fk.Close()
	if hasFK || fkErr != nil {
		return fmt.Errorf("invalid task delivery foreign keys: %v", fkErr)
	}

	var version, count int
	if err := db.QueryRow(`SELECT version,COUNT(*) FROM metadata GROUP BY version`).Scan(&version, &count); err != nil || version != 1 || count != 1 {
		return fmt.Errorf("invalid task delivery database metadata: version=%d count=%d: %v", version, count, err)
	}
	for _, name := range []string{"tasks", "acks", "one_active_per_node", "acks_by_task"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name=? AND type IN ('table','index')`, name).Scan(&n); err != nil || n != 1 {
			return fmt.Errorf("invalid task delivery database schema: missing %s", name)
		}
	}
	var bad int
	err = db.QueryRow(`
SELECT
 (SELECT COUNT(*) FROM tasks WHERE typeof(task_id)!='text' OR length(task_id)=0
   OR typeof(node_id)!='text' OR length(node_id)=0
   OR typeof(sequence)!='integer' OR sequence<1 OR sequence>?
   OR typeof(raw)!='blob' OR length(raw)=0
   OR typeof(key_id)!='text' OR length(key_id)=0
   OR typeof(active)!='integer' OR active NOT IN (0,1)
   OR (lease_id IS NOT NULL AND (typeof(lease_id)!='text' OR length(lease_id)=0))
   OR (lease_deadline IS NOT NULL AND typeof(lease_deadline)!='integer')) +
 (SELECT COUNT(*) FROM acks WHERE typeof(task_id)!='text' OR length(task_id)=0
   OR typeof(status_version)!='integer' OR status_version<1
   OR typeof(node_id)!='text' OR length(node_id)=0
   OR typeof(sequence)!='integer' OR sequence<1
   OR typeof(status)!='text' OR status NOT IN ('QUEUED','LEASED','ACK_ACCEPTED','RUNNING','VERIFYING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','EXPIRED','CANCELED','NEEDS_RECONCILIATION')
   OR typeof(result)!='blob' OR length(result)>4096) +
 (SELECT COUNT(*) FROM tasks t JOIN acks a ON a.task_id=t.task_id
   WHERE a.node_id!=t.node_id OR a.sequence!=t.sequence) +
 (SELECT COUNT(*) FROM tasks t WHERE t.active=0 AND NOT EXISTS
   (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND
    (a.status IN ('SUCCEEDED','ROLLED_BACK','EXPIRED','CANCELED') OR (a.status='FAILED' AND json_extract(CAST(t.raw AS TEXT),'$.operation')='core.status')))) +
 (SELECT COUNT(*) FROM tasks t WHERE t.active=1 AND EXISTS
   (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND
    (a.status IN ('SUCCEEDED','ROLLED_BACK','EXPIRED','CANCELED') OR (a.status='FAILED' AND json_extract(CAST(t.raw AS TEXT),'$.operation')='core.status'))))
`, MaxSequence).Scan(&bad)
	if err != nil || bad != 0 {
		return fmt.Errorf("invalid task delivery database contents: violations=%d: %v", bad, err)
	}
	rows, err := db.Query(`SELECT node_id,MIN(sequence),MAX(sequence),COUNT(*) FROM tasks GROUP BY node_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var node string
		var min, max, total int64
		if err := rows.Scan(&node, &min, &max, &total); err != nil {
			return err
		}
		if min != 1 || max != total {
			return fmt.Errorf("invalid task delivery sequence history for node %q", node)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var oversized int
	if err := db.QueryRow(`SELECT COUNT(*) FROM acks WHERE status_version>?`, MaxAckVersions).Scan(&oversized); err != nil {
		return err
	}
	if oversized != 0 {
		return errors.New("invalid task delivery ACK history limit")
	}
	ackRows, err := db.Query(`SELECT task_id,status_version,status FROM acks ORDER BY task_id,status_version`)
	if err != nil {
		return err
	}
	defer ackRows.Close()
	var task, previous string
	var ackVersion int64
	var rolledBack bool
	for ackRows.Next() {
		var current, status string
		var n int64
		if err := ackRows.Scan(&current, &n, &status); err != nil {
			return err
		}
		if current != task {
			task, ackVersion, previous = current, 0, ""
			rolledBack = false
		}
		if n != ackVersion+1 || (ackVersion != 0 && !validTransition(previous, status)) || (status == "ROLLING_BACK" && rolledBack) {
			return fmt.Errorf("invalid task delivery ACK history for task %q", current)
		}
		rolledBack = rolledBack || status == "ROLLING_BACK"
		ackVersion, previous = n, status
	}
	return ackRows.Err()
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Provision verifies the complete signed V2 task independently of the caller's
// identity claim, then stores the exact input bytes. authenticatedNodeID and
// the key ID/public key must come from trusted external configuration. The
// method never obtains identity, time, or keys from the task itself.
func (s *Store) Provision(authenticatedNodeID string, sequence int64, raw []byte, configuredKeyID string, configuredKey ed25519.PublicKey) error {
	if s == nil || s.db == nil || authenticatedNodeID == "" || sequence < 1 || sequence > MaxSequence || configuredKeyID == "" || len(configuredKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid provisioning arguments", ErrInvalid)
	}
	var body taskEnvelope
	if _, err := protocol.CanonicalV2TaskBytes(raw); err != nil {
		return fmt.Errorf("%w: task schema: %v", ErrInvalid, err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("%w: task fields: %v", ErrInvalid, err)
	}
	if body.NodeID != authenticatedNodeID || body.Sequence != sequence {
		return ErrIdentity
	}
	if body.KeyID != configuredKeyID {
		return ErrIdentity
	}
	if err := protocol.VerifyV2Task(raw, configuredKey); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	rawCopy := bytes.Clone(raw)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var existingNode, existingKey string
	var existingSeq int64
	var existingRaw []byte
	err = tx.QueryRow(`SELECT node_id,sequence,raw,key_id FROM tasks WHERE task_id=?`, body.TaskID).Scan(&existingNode, &existingSeq, &existingRaw, &existingKey)
	if err == nil {
		if existingNode != body.NodeID || existingSeq != sequence || existingKey != configuredKeyID || !bytes.Equal(existingRaw, rawCopy) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var slotNode string
	err = tx.QueryRow(`SELECT task_id FROM tasks WHERE node_id=? AND sequence=?`, body.NodeID, sequence).Scan(&slotNode)
	if err == nil {
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var active int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM tasks WHERE node_id=? AND active=1`, body.NodeID).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return ErrConflict
	}
	var maxSeq int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM tasks WHERE node_id=?`, body.NodeID).Scan(&maxSeq); err != nil {
		return err
	}
	if sequence != maxSeq+1 {
		return ErrSequence
	}
	if _, err = tx.Exec(`INSERT INTO tasks(task_id,node_id,sequence,raw,key_id,active) VALUES(?,?,?,?,?,1)`, body.TaskID, body.NodeID, sequence, rawCopy, configuredKeyID); err != nil {
		return err
	}
	return tx.Commit()
}

// Lease returns the exact provisioned bytes and creates a 60-second
// coordination lease. now is supplied by the caller; expiry permits delivery
// of the same task again and never creates a replacement task. The key ID and
// key must be supplied from trusted local configuration for every delivery.
func (s *Store) Lease(authenticatedNodeID string, now time.Time, configuredKeyID string, configuredKey ed25519.PublicKey) (Delivery, error) {
	var zero Delivery
	if s == nil || s.db == nil || authenticatedNodeID == "" || now.IsZero() || configuredKeyID == "" || len(configuredKey) != ed25519.PublicKeySize {
		return zero, fmt.Errorf("%w: invalid lease arguments", ErrInvalid)
	}
	leaseID, err := newLeaseID()
	if err != nil {
		return zero, err
	}
	deadline := now.Add(LeasePeriod)
	// UnixNano is undefined outside int64 nanoseconds. Check the full
	// instant before converting either endpoint, including near the limits.
	minTime := time.Unix(0, -1<<63)
	maxTime := time.Unix(0, 1<<63-1)
	if now.Before(minTime) || now.After(maxTime) || deadline.Before(minTime) || deadline.After(maxTime) {
		return zero, fmt.Errorf("%w: lease time outside representable range", ErrInvalid)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var d Delivery
	var storedKey string
	var lease sql.NullString
	var leaseDeadline sql.NullInt64
	err = tx.QueryRow(`SELECT node_id,task_id,sequence,raw,key_id,lease_id,lease_deadline FROM tasks WHERE node_id=? AND active=1`, authenticatedNodeID).Scan(&d.NodeID, &d.TaskID, &d.Sequence, &d.Raw, &storedKey, &lease, &leaseDeadline)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	var lastStatusVersion sql.NullInt64
	if err = tx.QueryRow(`SELECT MAX(status_version) FROM acks WHERE task_id=?`, d.TaskID).Scan(&lastStatusVersion); err != nil {
		return zero, err
	}
	if lastStatusVersion.Valid {
		d.LastStatusVersion = lastStatusVersion.Int64
	}
	if storedKey != configuredKeyID {
		return zero, ErrIdentity
	}
	if err := protocol.VerifyV2Task(d.Raw, configuredKey); err != nil {
		return zero, fmt.Errorf("%w: stored task: %v", ErrInvalid, err)
	}
	var body taskEnvelope
	if err := json.Unmarshal(d.Raw, &body); err != nil {
		return zero, fmt.Errorf("%w: stored task fields: %v", ErrInvalid, err)
	}
	if body.NodeID != authenticatedNodeID || body.NodeID != d.NodeID || body.TaskID != d.TaskID || body.Sequence != d.Sequence || body.KeyID != storedKey {
		return zero, ErrIdentity
	}
	var reconciliation int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM acks WHERE task_id=? AND status IN ('FAILED','ROLLING_BACK','NEEDS_RECONCILIATION')`, d.TaskID).Scan(&reconciliation); err != nil {
		return zero, err
	}
	if reconciliation != 0 {
		return zero, ErrConflict
	}
	if lease.Valid && leaseDeadline.Valid && leaseDeadline.Int64 > now.UnixNano() {
		return zero, ErrLeaseActive
	}
	if _, err = tx.Exec(`UPDATE tasks SET lease_id=?,lease_deadline=? WHERE task_id=? AND active=1`, leaseID, deadline.UnixNano(), d.TaskID); err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	d.Raw = bytes.Clone(d.Raw)
	d.LeaseID = leaseID
	d.Deadline = deadline
	return d, nil
}

// Acknowledge stores a node-bound, monotonically increasing status report.
// Same-version byte-for-byte duplicates succeed idempotently. A terminal ACK
// closes the slot; later newer ACKs are rejected. No ACK is an execution hook.
func (s *Store) Acknowledge(authenticatedNodeID string, ack Ack) error {
	if s == nil || s.db == nil || authenticatedNodeID == "" || ack.NodeID == "" || ack.NodeID != authenticatedNodeID || ack.TaskID == "" || ack.Sequence < 1 || ack.StatusVersion < 1 || len(ack.Result) > MaxResultBytes || !allowedStatuses[ack.Status] {
		return fmt.Errorf("%w: invalid ACK arguments", ErrInvalid)
	}
	resultCopy := bytes.Clone(ack.Result)
	if resultCopy == nil {
		resultCopy = []byte{}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var taskNode string
	var taskSeq int64
	var active int
	var raw []byte
	err = tx.QueryRow(`SELECT node_id,sequence,active,raw FROM tasks WHERE task_id=?`, ack.TaskID).Scan(&taskNode, &taskSeq, &active, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if taskNode != authenticatedNodeID || taskSeq != ack.Sequence {
		return ErrIdentity
	}
	var operation struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(raw, &operation) != nil {
		return ErrIdentity
	}
	var oldNode, oldStatus string
	var oldSeq, oldVersion int64
	var oldResult []byte
	err = tx.QueryRow(`SELECT node_id,sequence,status_version,status,result FROM acks WHERE task_id=? AND status_version=?`, ack.TaskID, ack.StatusVersion).Scan(&oldNode, &oldSeq, &oldVersion, &oldStatus, &oldResult)
	if err == nil {
		if oldNode == ack.NodeID && oldSeq == ack.Sequence && oldVersion == ack.StatusVersion && oldStatus == ack.Status && bytes.Equal(oldResult, resultCopy) {
			return tx.Commit()
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if ack.StatusVersion > MaxAckVersions {
		return ErrConflict
	}
	var maxVersion sql.NullInt64
	if err = tx.QueryRow(`SELECT MAX(status_version) FROM acks WHERE task_id=?`, ack.TaskID).Scan(&maxVersion); err != nil {
		return err
	}
	if (!maxVersion.Valid && ack.StatusVersion != 1) || (maxVersion.Valid && (maxVersion.Int64 == int64(^uint64(0)>>1) || ack.StatusVersion != maxVersion.Int64+1)) {
		return ErrConflict
	}
	if active == 0 {
		return ErrConflict
	}
	if maxVersion.Valid {
		var previous string
		if err = tx.QueryRow(`SELECT status FROM acks WHERE task_id=? AND status_version=?`, ack.TaskID, maxVersion.Int64).Scan(&previous); err != nil {
			return err
		}
		if !validTransition(previous, ack.Status) {
			return ErrConflict
		}
	}
	if ack.Status == "ROLLING_BACK" {
		var prior int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM acks WHERE task_id=? AND status='ROLLING_BACK'`, ack.TaskID).Scan(&prior); err != nil {
			return err
		}
		if prior != 0 {
			return ErrConflict
		}
	}
	if _, err = tx.Exec(`INSERT INTO acks(task_id,status_version,node_id,sequence,status,result) VALUES(?,?,?,?,?,?)`, ack.TaskID, ack.StatusVersion, ack.NodeID, ack.Sequence, ack.Status, resultCopy); err != nil {
		return err
	}
	if terminalStatuses[ack.Status] || (ack.Status == "FAILED" && operation.Operation == "core.status") {
		if _, err = tx.Exec(`UPDATE tasks SET active=0,lease_id=NULL,lease_deadline=NULL WHERE task_id=? AND active=1`, ack.TaskID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func newLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Observations may skip intermediate states, but cannot move backwards. Once
// reconciliation is needed, this storage boundary cannot authorize resolution.
func validTransition(from, to string) bool {
	if from == "NEEDS_RECONCILIATION" || terminalStatuses[from] {
		return false
	}
	if to == "NEEDS_RECONCILIATION" {
		return true
	}
	switch from {
	case "QUEUED":
		return to != "QUEUED"
	case "LEASED":
		return to != "QUEUED" && to != "LEASED"
	case "ACK_ACCEPTED":
		return to != "QUEUED" && to != "LEASED" && to != "ACK_ACCEPTED"
	case "RUNNING":
		return to == "VERIFYING" || to == "SUCCEEDED" || to == "FAILED" || to == "ROLLING_BACK" || to == "ROLLED_BACK"
	case "VERIFYING":
		return to == "SUCCEEDED" || to == "FAILED" || to == "ROLLING_BACK" || to == "ROLLED_BACK"
	case "FAILED":
		return to == "ROLLING_BACK" || to == "ROLLED_BACK"
	case "ROLLING_BACK":
		return to == "ROLLED_BACK" || to == "FAILED"
	}
	return false
}
