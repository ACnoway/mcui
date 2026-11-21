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
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/protocol"
	"github.com/ACnoway/mcui/internal/taskcontrol"
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
	ControlKind       string
	ControlRaw        []byte
	LeaseID           string
	Deadline          time.Time
	LastStatusVersion int64
	SequenceRecovery  bool
	SequenceSkip      bool
	ReconcileInstall  bool
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
	SignedManifest bool      `json:"-"`
	SchemaVersion  int       `json:"schema_version"`
	TaskID         string    `json:"task_id"`
	NodeID         string    `json:"node_id"`
	Sequence       int64     `json:"sequence"`
	KeyID          string    `json:"signing_key_id"`
	Operation      string    `json:"operation"`
	ExpiresAt      time.Time `json:"expires_at"`
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

// Open opens an initialized database, validates its schema and durable
// invariants, and applies only the known additive task-controls migration.
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
	if err = ensureControlSchema(s.db); err != nil {
		_ = s.Close()
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
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
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
CREATE TABLE task_controls (
 task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
 kind TEXT NOT NULL CHECK(kind IN ('cancel','skip')),
 raw BLOB NOT NULL CHECK(typeof(raw)='blob' AND length(raw)>0 AND length(raw)<=65536)
);
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
		// Existing Phase 2 databases predate online control delivery. Accept
		// only the exact prior schema; Open adds the isolated control table.
		if len(got) != len(want)-2 {
			return errors.New("invalid task delivery database schema objects")
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			return fmt.Errorf("unexpected task delivery schema object %q", k)
		}
	}
	controlsPresent := true
	for k, v := range want {
		if k == "table\x00task_controls" || k == "index\x00sqlite_autoindex_task_controls_1" {
			continue
		}
		if got[k] != v {
			return fmt.Errorf("invalid task delivery schema object %q", k)
		}
	}
	if _, ok := got["table\x00task_controls"]; !ok {
		controlsPresent = false
		if _, unexpected := got["index\x00sqlite_autoindex_task_controls_1"]; unexpected {
			return errors.New("invalid task control schema index")
		}
	} else if got["table\x00task_controls"] != want["table\x00task_controls"] || got["index\x00sqlite_autoindex_task_controls_1"] != want["index\x00sqlite_autoindex_task_controls_1"] {
		return errors.New("invalid task control schema")
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
 (SELECT COUNT(*) FROM tasks t WHERE t.active=1 AND EXISTS
   (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND
    (a.status IN ('SUCCEEDED','ROLLED_BACK','EXPIRED','CANCELED') OR (a.status='FAILED' AND (`+terminalFailureSQL+`)))))
`, MaxSequence).Scan(&bad)
	if err != nil || bad != 0 {
		return fmt.Errorf("invalid task delivery database contents: violations=%d: %v", bad, err)
	}
	if controlsPresent {
		if err = db.QueryRow(`SELECT COUNT(*) FROM tasks t WHERE t.active=0 AND NOT EXISTS
 (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND
  (a.status IN ('SUCCEEDED','ROLLED_BACK','EXPIRED','CANCELED') OR (a.status='FAILED' AND (` + terminalFailureSQL + `))))
 AND NOT EXISTS (SELECT 1 FROM task_controls c WHERE c.task_id=t.task_id AND c.kind='skip'
   AND json_extract(CAST(c.raw AS TEXT),'$.reason')='VOID_UNISSUED' AND t.lease_id IS NULL AND t.lease_deadline IS NULL)`).Scan(&bad); err != nil || bad != 0 {
			return fmt.Errorf("invalid terminal task data: violations=%d: %v", bad, err)
		}
		if err = db.QueryRow(`SELECT COUNT(*) FROM task_controls c JOIN tasks t ON t.task_id=c.task_id
 WHERE typeof(c.task_id)!='text' OR length(c.task_id)=0
    OR typeof(c.kind)!='text' OR c.kind NOT IN ('cancel','skip')
    OR typeof(c.raw)!='blob' OR length(c.raw)=0 OR length(c.raw)>65536
    OR NOT (
      (t.active=1 AND NOT EXISTS (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND a.status IN ('RUNNING','VERIFYING','SUCCEEDED','FAILED','ROLLING_BACK','ROLLED_BACK','EXPIRED','CANCELED','NEEDS_RECONCILIATION')))
      OR (t.active=0 AND c.kind='skip' AND EXISTS (SELECT 1 FROM acks a WHERE a.task_id=t.task_id AND (a.status IN ('SUCCEEDED','ROLLED_BACK','EXPIRED','CANCELED') OR (a.status='FAILED' AND (` + terminalFailureSQL + `)))))
      OR (t.active=0 AND c.kind='skip' AND NOT EXISTS (SELECT 1 FROM acks a WHERE a.task_id=t.task_id) AND t.lease_id IS NULL AND t.lease_deadline IS NULL AND json_extract(CAST(c.raw AS TEXT),'$.reason')='VOID_UNISSUED')
    )`).Scan(&bad); err != nil || bad != 0 {
			return fmt.Errorf("invalid task control data: violations=%d: %v", bad, err)
		}
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
	ackRows, err := db.Query(`SELECT a.task_id,a.status_version,a.status,COALESCE((` + xrayTaskSQL + `),0) FROM acks a JOIN tasks t ON t.task_id=a.task_id ORDER BY a.task_id,a.status_version`)
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
		var xrayTask bool
		if err := ackRows.Scan(&current, &n, &status, &xrayTask); err != nil {
			return err
		}
		if current != task {
			task, ackVersion, previous = current, 0, ""
			rolledBack = false
		}
		if n != ackVersion+1 || (ackVersion != 0 && !validTransition(previous, status, xrayTask)) || (status == "ROLLING_BACK" && rolledBack) {
			return fmt.Errorf("invalid task delivery ACK history for task %q", current)
		}
		rolledBack = rolledBack || status == "ROLLING_BACK"
		ackVersion, previous = n, status
	}
	return ackRows.Err()
}

// ensureControlSchema adds the isolated control table after Open has verified
// that the pre-control database is exactly the known legacy schema. Existing
// task and ACK rows remain untouched.
func ensureControlSchema(db *sql.DB) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='task_controls'`).Scan(&count); err != nil {
		return err
	}
	if count == 1 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`CREATE TABLE task_controls (
 task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
 kind TEXT NOT NULL CHECK(kind IN ('cancel','skip')),
 raw BLOB NOT NULL CHECK(typeof(raw)='blob' AND length(raw)>0 AND length(raw)<=65536)
)`); err != nil {
		return err
	}
	return tx.Commit()
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
	return s.provision(body, raw)
}

func (s *Store) ProvisionInstall(raw []byte, key lifecycleauth.InstallKey, now time.Time) error {
	task, err := key.Verify(raw)
	if err != nil || !task.ActiveAt(now) {
		return ErrIdentity
	}
	return s.provision(taskEnvelope{SchemaVersion: 1, TaskID: task.TaskID, NodeID: task.NodeID, Sequence: task.Sequence, KeyID: task.KeyID, Operation: task.Operation, ExpiresAt: task.ExpiresAt}, raw)
}

func (s *Store) provision(body taskEnvelope, raw []byte) error {
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
		if existingNode != body.NodeID || existingSeq != body.Sequence || existingKey != body.KeyID || !bytes.Equal(existingRaw, rawCopy) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var slotNode string
	err = tx.QueryRow(`SELECT task_id FROM tasks WHERE node_id=? AND sequence=?`, body.NodeID, body.Sequence).Scan(&slotNode)
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
	if body.Sequence != maxSeq+1 {
		return ErrSequence
	}
	if _, err = tx.Exec(`INSERT INTO tasks(task_id,node_id,sequence,raw,key_id,active) VALUES(?,?,?,?,?,1)`, body.TaskID, body.NodeID, body.Sequence, rawCopy, body.KeyID); err != nil {
		return err
	}
	return tx.Commit()
}

// Lease returns the exact provisioned bytes and creates a 60-second
// coordination lease. now is supplied by the caller; expiry permits delivery
// of the same task again and never creates a replacement task. The key ID and
// key must be supplied from trusted local configuration for every delivery.
func (s *Store) Lease(authenticatedNodeID string, now time.Time, configuredKeyID string, configuredKey ed25519.PublicKey) (Delivery, error) {
	return s.lease(authenticatedNodeID, now, configuredKeyID, configuredKey, 0, nil, lifecycleauth.InstallKey{}, "", false, false)
}

// LeaseExpected reconciles the Agent's durable next sequence before leasing
// the current task. Missing historical terminal slots receive signed EXPIRED
// skips; a never-delivered task can be closed with VOID_UNISSUED.
func (s *Store) LeaseExpected(authenticatedNodeID string, now time.Time, configuredKeyID string, configuredKey ed25519.PublicKey, expectedSequence int64, buildSkip func(sequence int64, reason string) ([]byte, error)) (Delivery, error) {
	if expectedSequence < 1 || expectedSequence > MaxSequence || buildSkip == nil {
		return Delivery{}, fmt.Errorf("%w: invalid expected sequence recovery", ErrInvalid)
	}
	return s.lease(authenticatedNodeID, now, configuredKeyID, configuredKey, expectedSequence, buildSkip, lifecycleauth.InstallKey{}, "", false, false)
}

func (s *Store) LeaseWithInstall(nodeID string, now time.Time, statusKeyID string, statusKey ed25519.PublicKey, expected int64, buildSkip func(int64, string) ([]byte, error), installKey lifecycleauth.InstallKey, mode string, reconcileInstall, controlCapable bool) (Delivery, error) {
	if expected < 0 || expected > MaxSequence || expected > 0 && buildSkip == nil {
		return Delivery{}, ErrInvalid
	}
	return s.lease(nodeID, now, statusKeyID, statusKey, expected, buildSkip, installKey, mode, reconcileInstall, controlCapable)
}

func (s *Store) lease(authenticatedNodeID string, now time.Time, configuredKeyID string, configuredKey ed25519.PublicKey, expectedSequence int64, buildSkip func(sequence int64, reason string) ([]byte, error), installKey lifecycleauth.InstallKey, mode string, reconcileInstall, controlCapable bool) (Delivery, error) {
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
	installCapable := expectedSequence > 0 && (mode == "xray-v1" || mode == "xray-manifest-v1")
	if expectedSequence > 0 {
		recovery, isRecovery, recoverErr := s.recoverExpectedSequence(tx, authenticatedNodeID, expectedSequence, now, configuredKeyID, configuredKey, buildSkip, installKey, installCapable, controlCapable)
		if recoverErr != nil {
			return zero, recoverErr
		}
		if isRecovery {
			if err = tx.Commit(); err != nil {
				return zero, err
			}
			return recovery, nil
		}
	}
	var d Delivery
	var storedKey string
	var lease sql.NullString
	var leaseDeadline sql.NullInt64
	var controlKind sql.NullString
	err = tx.QueryRow(`SELECT t.node_id,t.task_id,t.sequence,t.raw,t.key_id,t.lease_id,t.lease_deadline,c.kind,c.raw FROM tasks t LEFT JOIN task_controls c ON c.task_id=t.task_id WHERE t.node_id=? AND t.active=1`, authenticatedNodeID).Scan(&d.NodeID, &d.TaskID, &d.Sequence, &d.Raw, &storedKey, &lease, &leaseDeadline, &controlKind, &d.ControlRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return zero, ErrNotFound
	}
	if err != nil {
		return zero, err
	}
	var lastStatus string
	if err = tx.QueryRow(`SELECT status_version,status FROM acks WHERE task_id=? ORDER BY status_version DESC LIMIT 1`, d.TaskID).Scan(&d.LastStatusVersion, &lastStatus); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return zero, err
	}
	if controlKind.Valid {
		d.ControlKind = controlKind.String
	}
	body, err := verifyDeliveryTask(d.Raw, storedKey, configuredKeyID, configuredKey, installKey, installCapable, controlCapable)
	if err != nil {
		return zero, err
	}
	if body.Operation == "core.install" && body.SignedManifest != (mode == "xray-manifest-v1") {
		return zero, ErrNotFound
	}
	if body.NodeID != authenticatedNodeID || body.NodeID != d.NodeID || body.TaskID != d.TaskID || body.Sequence != d.Sequence || body.KeyID != storedKey {
		return zero, ErrIdentity
	}
	if controlKind.Valid {
		kind := protocol.Kind(controlKind.String)
		control, controlErr := taskcontrol.Verify(kind, d.ControlRaw, taskcontrol.Trust{NodeID: authenticatedNodeID, KeyID: configuredKeyID, Purpose: taskcontrol.PurposeTask, PublicKey: configuredKey, Now: now})
		if errors.Is(controlErr, taskcontrol.ErrTime) {
			var timeBounds struct {
				ExpiresAt time.Time `json:"expires_at"`
			}
			if json.Unmarshal(d.ControlRaw, &timeBounds) == nil && !timeBounds.ExpiresAt.IsZero() && !now.Before(timeBounds.ExpiresAt) {
				if _, err = tx.Exec(`DELETE FROM task_controls WHERE task_id=?`, d.TaskID); err != nil {
					return zero, err
				}
				d.ControlKind = ""
				d.ControlRaw = nil
				controlKind.Valid = false
			} else {
				return zero, fmt.Errorf("%w: stored control is not currently valid", ErrInvalid)
			}
		} else if controlErr != nil || control.NodeID != d.NodeID || int64(control.Sequence) != d.Sequence || (kind == protocol.Cancel && control.TaskID != d.TaskID) || (kind == protocol.Skip && (control.Reason != "EXPIRED" || body.ExpiresAt.IsZero() || now.Before(body.ExpiresAt) || control.IssuedAt.Before(body.ExpiresAt))) {
			return zero, fmt.Errorf("%w: stored control message", ErrInvalid)
		}
	}
	if lastStatus == "NEEDS_RECONCILIATION" && isXrayTask(body) && reconcileInstall && !controlKind.Valid {
		// The fenced envelope is delivered without any execution lease.
		if lease.Valid || leaseDeadline.Valid {
			if _, err = tx.Exec(`UPDATE tasks SET lease_id=NULL,lease_deadline=NULL WHERE task_id=?`, d.TaskID); err != nil {
				return zero, err
			}
		}
		d.ReconcileInstall = true
		return d, tx.Commit()
	}
	if lastStatus == "FAILED" || lastStatus == "ROLLING_BACK" || lastStatus == "NEEDS_RECONCILIATION" {
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
	d.ControlRaw = bytes.Clone(d.ControlRaw)
	d.LeaseID = leaseID
	d.Deadline = deadline
	return d, nil
}

func (s *Store) recoverExpectedSequence(tx *sql.Tx, nodeID string, expected int64, now time.Time, keyID string, publicKey ed25519.PublicKey, buildSkip func(int64, string) ([]byte, error), installKey lifecycleauth.InstallKey, installCapable, controlCapable bool) (Delivery, bool, error) {
	var activeSequence sql.NullInt64
	if err := tx.QueryRow(`SELECT sequence FROM tasks WHERE node_id=? AND active=1`, nodeID).Scan(&activeSequence); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, false, err
	}
	var highWater int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(sequence),0) FROM tasks WHERE node_id=?`, nodeID).Scan(&highWater); err != nil {
		return Delivery{}, false, err
	}
	if activeSequence.Valid && expected > activeSequence.Int64 {
		if installCapable && expected == activeSequence.Int64+1 {
			var raw []byte
			if err := tx.QueryRow(`SELECT raw FROM tasks WHERE node_id=? AND sequence=? AND active=1`, nodeID, activeSequence.Int64).Scan(&raw); err != nil {
				return Delivery{}, false, err
			}
			if task, err := installKey.Verify(raw); err == nil && task.NodeID == nodeID && task.Sequence == activeSequence.Int64 &&
				(!lifecycleauth.IsControlOperation(task.Operation) || controlCapable) {
				return Delivery{}, false, nil // Agent can replay its durable terminal ACK.
			}
		}
		return Delivery{}, false, ErrSequence
	}
	if !activeSequence.Valid && expected > highWater+1 {
		return Delivery{}, false, ErrSequence
	}
	if expected > highWater {
		return Delivery{}, false, nil
	}

	var d Delivery
	var storedKey string
	var active int
	var lease sql.NullString
	var deadline sql.NullInt64
	var controlKind sql.NullString
	err := tx.QueryRow(`SELECT t.task_id,t.node_id,t.sequence,t.raw,t.key_id,t.active,t.lease_id,t.lease_deadline,c.kind,c.raw FROM tasks t LEFT JOIN task_controls c ON c.task_id=t.task_id WHERE t.node_id=? AND t.sequence=?`, nodeID, expected).Scan(&d.TaskID, &d.NodeID, &d.Sequence, &d.Raw, &storedKey, &active, &lease, &deadline, &controlKind, &d.ControlRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, false, ErrSequence
	}
	if err != nil {
		return Delivery{}, false, err
	}
	if active == 1 && activeSequence.Valid && expected == activeSequence.Int64 {
		return Delivery{}, false, nil
	}
	body, err := verifyDeliveryTask(d.Raw, storedKey, keyID, publicKey, installKey, installCapable, controlCapable)
	if err != nil || body.TaskID != d.TaskID || body.NodeID != nodeID || body.Sequence != expected || body.KeyID != storedKey {
		return Delivery{}, false, ErrIdentity
	}
	if active != 0 && active != 1 {
		return Delivery{}, false, ErrConflict
	}
	if active == 0 && controlKind.Valid && controlKind.String == string(protocol.Skip) {
		var fields struct {
			NodeID    string    `json:"node_id"`
			Sequence  uint64    `json:"sequence"`
			Reason    string    `json:"reason"`
			KeyID     string    `json:"signing_key_id"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if protocol.Verify(protocol.Skip, d.ControlRaw, publicKey) != nil || json.Unmarshal(d.ControlRaw, &fields) != nil || fields.NodeID != nodeID || fields.Sequence != uint64(expected) || fields.KeyID != keyID || fields.Reason != "VOID_UNISSUED" || fields.ExpiresAt.IsZero() {
			return Delivery{}, false, ErrIdentity
		}
		if !now.Before(fields.ExpiresAt) {
			replacement, signErr := buildSkip(expected, "VOID_UNISSUED")
			if signErr != nil {
				return Delivery{}, false, signErr
			}
			verified, verifyErr := taskcontrol.Verify(protocol.Skip, replacement, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
			if verifyErr != nil || verified.Sequence != uint64(expected) || verified.Reason != "VOID_UNISSUED" {
				return Delivery{}, false, ErrIdentity
			}
			if _, err = tx.Exec(`UPDATE task_controls SET raw=? WHERE task_id=? AND kind='skip'`, replacement, d.TaskID); err != nil {
				return Delivery{}, false, err
			}
			d.ControlRaw = bytes.Clone(replacement)
		} else {
			verified, verifyErr := taskcontrol.Verify(protocol.Skip, d.ControlRaw, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
			if verifyErr != nil || verified.Sequence != uint64(expected) || verified.Reason != "VOID_UNISSUED" {
				return Delivery{}, false, ErrIdentity
			}
		}
		if lease.Valid || deadline.Valid {
			return Delivery{}, false, ErrConflict
		}
		id, idErr := newLeaseID()
		if idErr != nil {
			return Delivery{}, false, idErr
		}
		d.ControlKind, d.LeaseID, d.SequenceSkip = string(protocol.Skip), id, true
		d.Raw = nil
		d.ControlRaw = bytes.Clone(d.ControlRaw)
		return d, true, nil
	}
	if active != 0 || buildSkip == nil {
		return Delivery{}, false, ErrSequence
	}
	var terminal string
	if err = tx.QueryRow(`SELECT status FROM acks WHERE task_id=? ORDER BY status_version DESC LIMIT 1`, d.TaskID).Scan(&terminal); err != nil {
		return Delivery{}, false, ErrSequence
	}
	if !terminalStatuses[terminal] && !(terminal == "FAILED" && isTerminalFailure(body)) {
		return Delivery{}, false, ErrSequence
	}
	if now.Before(body.ExpiresAt) {
		return Delivery{}, false, ErrSequence
	}
	if controlKind.Valid && controlKind.String != string(protocol.Skip) {
		return Delivery{}, false, ErrConflict
	}

	var fields struct {
		NodeID    string    `json:"node_id"`
		Sequence  uint64    `json:"sequence"`
		Reason    string    `json:"reason"`
		KeyID     string    `json:"signing_key_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	needSign := true
	if controlKind.Valid {
		if protocol.Verify(protocol.Skip, d.ControlRaw, publicKey) != nil || json.Unmarshal(d.ControlRaw, &fields) != nil || fields.NodeID != nodeID || fields.Sequence != uint64(expected) || fields.KeyID != keyID || fields.Reason != "EXPIRED" {
			return Delivery{}, false, ErrIdentity
		}
		if now.Before(fields.ExpiresAt) {
			verified, verifyErr := taskcontrol.Verify(protocol.Skip, d.ControlRaw, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
			if verifyErr == nil && verified.Sequence == uint64(expected) && verified.Reason == "EXPIRED" {
				needSign = false
			}
		}
	}
	if needSign {
		controlRaw, signErr := buildSkip(expected, "EXPIRED")
		if signErr != nil {
			return Delivery{}, false, signErr
		}
		verified, verifyErr := taskcontrol.Verify(protocol.Skip, controlRaw, taskcontrol.Trust{NodeID: nodeID, KeyID: keyID, Purpose: taskcontrol.PurposeTask, PublicKey: publicKey, Now: now})
		if verifyErr != nil || verified.Sequence != uint64(expected) || verified.Reason != "EXPIRED" {
			return Delivery{}, false, ErrIdentity
		}
		if _, err = tx.Exec(`INSERT INTO task_controls(task_id,kind,raw) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET kind=excluded.kind,raw=excluded.raw`, d.TaskID, string(protocol.Skip), controlRaw); err != nil {
			return Delivery{}, false, err
		}
		d.ControlRaw = bytes.Clone(controlRaw)
	}
	var lastStatus sql.NullInt64
	if err = tx.QueryRow(`SELECT MAX(status_version) FROM acks WHERE task_id=?`, d.TaskID).Scan(&lastStatus); err != nil {
		return Delivery{}, false, err
	}
	if lastStatus.Valid {
		d.LastStatusVersion = lastStatus.Int64
	}
	id, err := newLeaseID()
	if err != nil {
		return Delivery{}, false, err
	}
	d.ControlKind, d.LeaseID, d.SequenceRecovery = string(protocol.Skip), id, true
	d.Raw, d.ControlRaw = bytes.Clone(d.Raw), bytes.Clone(d.ControlRaw)
	return d, true, nil
}

func verifyDeliveryTask(raw []byte, storedKey, statusKeyID string, statusKey ed25519.PublicKey, installKey lifecycleauth.InstallKey, installCapable, controlCapable bool) (taskEnvelope, error) {
	var body taskEnvelope
	if storedKey == statusKeyID {
		if err := protocol.VerifyV2Task(raw, statusKey); err != nil {
			return body, fmt.Errorf("%w: stored task: %v", ErrInvalid, err)
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return body, fmt.Errorf("%w: stored task fields: %v", ErrInvalid, err)
		}
		return body, nil
	}
	if storedKey == installKey.ID && installKey.ID != "" {
		if !installCapable {
			return body, ErrNotFound
		}
		if task, err := installKey.Verify(raw); err == nil {
			if lifecycleauth.IsControlOperation(task.Operation) && !controlCapable {
				return body, ErrNotFound
			}
			return taskEnvelope{SchemaVersion: 1, TaskID: task.TaskID, NodeID: task.NodeID, Sequence: task.Sequence, KeyID: task.KeyID, Operation: task.Operation, ExpiresAt: task.ExpiresAt, SignedManifest: task.SignedManifest}, nil
		}
	}
	return body, ErrIdentity
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
	var operation taskEnvelope
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
		if !validTransition(previous, ack.Status, isXrayTask(operation)) {
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
	terminal := terminalStatuses[ack.Status] || (ack.Status == "FAILED" && isTerminalFailure(operation))
	if terminal {
		if _, err = tx.Exec(`UPDATE tasks SET active=0,lease_id=NULL,lease_deadline=NULL WHERE task_id=? AND active=1`, ack.TaskID); err != nil {
			return err
		}
	}
	if ack.Status == "NEEDS_RECONCILIATION" && isXrayTask(operation) {
		if _, err = tx.Exec(`UPDATE tasks SET lease_id=NULL,lease_deadline=NULL WHERE task_id=?`, ack.TaskID); err != nil {
			return err
		}
	}
	if ack.Status == "RUNNING" || ack.Status == "NEEDS_RECONCILIATION" || terminal {
		if _, err = tx.Exec(`DELETE FROM task_controls WHERE task_id=?`, ack.TaskID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// An Xray task reports FAILED before changing the service. A rollback has its
// own terminal state and an uncertain outcome fences the sequence.
func isTerminalFailure(task taskEnvelope) bool {
	return task.Operation == "core.status" || isXrayTask(task)
}

func isXrayTask(task taskEnvelope) bool {
	return task.SchemaVersion == 1 && (task.Operation == "core.install" || lifecycleauth.IsControlOperation(task.Operation))
}

const xrayTaskSQL = `json_extract(CAST(t.raw AS TEXT),'$.schema_version')=1 AND json_extract(CAST(t.raw AS TEXT),'$.operation') IN ('core.install','core.start','core.stop')`
const terminalFailureSQL = `json_extract(CAST(t.raw AS TEXT),'$.operation')='core.status' OR (` + xrayTaskSQL + `)`

func newLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Only Xray lifecycle tasks can resolve a fenced observation.
func validTransition(from, to string, xrayTask bool) bool {
	if from == "NEEDS_RECONCILIATION" {
		return xrayTask && (to == "SUCCEEDED" || to == "ROLLED_BACK")
	}
	if terminalStatuses[from] {
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
