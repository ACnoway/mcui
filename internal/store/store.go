package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"modernc.org/sqlite"
)

var ErrNotFound = errors.New("record not found")

const schemaVersion = 3

const driverName = "mcui-master-sqlite"

func init() {
	driver := &sqlite.Driver{}
	driver.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, _ string) error {
		for _, query := range []string{
			"PRAGMA busy_timeout=5000",
			"PRAGMA journal_mode=WAL",
			"PRAGMA synchronous=FULL",
			"PRAGMA foreign_keys=ON",
		} {
			if _, err := conn.ExecContext(context.Background(), query, nil); err != nil {
				return err
			}
		}
		return nil
	})
	sql.Register(driverName, driver)
}

type State struct {
	Admins map[string]Admin `json:"admins"`

	Nodes    map[string]Node    `json:"nodes"`
	Sessions map[string]Session `json:"sessions"`

	Audits       []Audit                `json:"audits"`
	XrayInstalls map[string]XrayInstall `json:"xray_installs,omitempty"`
}

// XrayInstall retains the proposal and authorization digest independently of the
// bounded audit log. The proposal is preserved as the exact exported JSON.
type XrayInstall struct {
	Proposal   json.RawMessage `json:"proposal"`
	ApprovalID string          `json:"approval_id,omitempty"` // Existing storage key for the authorization digest.
	SignedTask json.RawMessage `json:"signed_task,omitempty"`
}

type Admin struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	TOTPSecret   string   `json:"totp_secret"`
	Role         string   `json:"role"`
	NodeIDs      []string `json:"node_ids,omitempty"`
	NodeGroups   []string `json:"node_groups,omitempty"`
	AllNodes     bool     `json:"all_nodes,omitempty"`
	Disabled     bool     `json:"disabled"`
}

type Node struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Group                string `json:"group"`
	LastSeen             int64  `json:"last_seen"`
	Disabled             bool   `json:"disabled"`
	Enrolled             bool   `json:"enrolled,omitempty"`
	TokenHash            string `json:"node_token_hash,omitempty"`
	InstallCodeHash      string `json:"install_code_hash,omitempty"`
	InstallCodeExpiresAt int64  `json:"install_code_expires_at,omitempty"`
}

type Session struct {
	ID        string `json:"id"`
	AdminID   string `json:"admin_id"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	MFAAt     int64  `json:"mfa_at"`
	CSRFToken string `json:"csrf_token"`
}

type Audit struct {
	At           int64  `json:"at"`
	Actor        string `json:"actor"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type,omitempty"`
	Resource     string `json:"resource"`
	NodeID       string `json:"node_id,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Outcome      string `json:"outcome"`
}

type Store struct {
	mu sync.RWMutex
	db *sql.DB
}

type executor interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func Open(path string) (*Store, error) {
	db, err := sql.Open(driverName, path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// OpenExisting opens a regular database without creating a replacement for a
// missing file. A checkpoint-enabled Master requires an explicitly enrolled DB.
func OpenExisting(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("panel database must be a regular file")
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath, RawQuery: "mode=rw"}
	return Open(uri.String())
}

func migrate(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	var current int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if current > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", current, schemaVersion)
	}
	if current == 0 {
		for _, query := range schemaV2 {
			if _, err := tx.Exec(query); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(createXrayInstalls); err != nil {
			return err
		}
		state := emptyState()
		var legacyExists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_state'`).Scan(&legacyExists); err != nil {
			return err
		}
		if legacyExists == 1 {
			var payload []byte
			if err := tx.QueryRow(`SELECT payload FROM app_state WHERE id=1`).Scan(&payload); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			} else if err == nil {
				state, err = decode(payload)
				if err != nil {
					return fmt.Errorf("migrate legacy database state: %w", err)
				}
			}
		}
		if err := persistState(tx, state); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES(?)`, schemaVersion); err != nil {
			return err
		}
		if legacyExists == 1 {
			if _, err := tx.Exec(`DROP TABLE app_state`); err != nil {
				return err
			}
		}
	}
	if current == 1 {
		for _, query := range upgradeV1 {
			if _, err := tx.Exec(query); err != nil {
				return err
			}
		}
	}
	if current == 1 || current == 2 {
		if _, err := tx.Exec(createXrayInstalls); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations(version) VALUES(?)", schemaVersion); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const createXrayInstalls = `CREATE TABLE xray_installs (id TEXT PRIMARY KEY, payload BLOB NOT NULL)`

var upgradeV1 = []string{
	"DROP TABLE enrollments",
	"DROP TABLE invites",
	"UPDATE nodes SET payload = json_set(json_remove(CAST(payload AS TEXT), '$.public_key', '$.certificates', '$.current_serial', '$.cert_requests', '$.needs_reenrollment', '$.token_hash'), '$.enrolled', json('true'))",
}

var schemaV2 = []string{
	`CREATE TABLE IF NOT EXISTS admins (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, role TEXT NOT NULL, disabled INTEGER NOT NULL, payload BLOB NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, node_group TEXT NOT NULL, last_seen INTEGER NOT NULL, disabled INTEGER NOT NULL, payload BLOB NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS nodes_group_seen_idx ON nodes(node_group, last_seen)`,
	`CREATE TABLE IF NOT EXISTS sessions (id_hash TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL, payload BLOB NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS sessions_admin_idx ON sessions(admin_id, expires_at)`,
	`CREATE TABLE IF NOT EXISTS audit_logs (event_seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, resource_type TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL, payload BLOB NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS audit_resource_idx ON audit_logs(resource_type, resource, at)`,
}

func emptyState() State {
	return State{Admins: map[string]Admin{}, Nodes: map[string]Node{}, Sessions: map[string]Session{}, Audits: []Audit{}, XrayInstalls: map[string]XrayInstall{}}
}

func decode(payload []byte) (State, error) {
	state := emptyState()
	if string(payload) == "{}" || len(payload) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(payload, &state); err != nil {
		return State{}, err
	}
	if state.Admins == nil {
		state.Admins = map[string]Admin{}
	}
	if state.Nodes == nil {
		state.Nodes = map[string]Node{}
	}
	if state.Sessions == nil {
		state.Sessions = map[string]Session{}
	}
	if state.Audits == nil {
		state.Audits = []Audit{}
	}
	for id, node := range state.Nodes {
		node.Enrolled = true
		node.TokenHash, node.InstallCodeHash, node.InstallCodeExpiresAt = "", "", 0
		state.Nodes[id] = node
	}
	return state, nil
}

func loadState(q executor) (State, error) {
	state := emptyState()
	if err := loadMap(q, `SELECT id, payload FROM admins ORDER BY id`, state.Admins); err != nil {
		return State{}, err
	}
	if err := loadMap(q, `SELECT id, payload FROM nodes ORDER BY id`, state.Nodes); err != nil {
		return State{}, err
	}
	if err := loadMap(q, `SELECT id_hash, payload FROM sessions ORDER BY id_hash`, state.Sessions); err != nil {
		return State{}, err
	}
	if err := loadMap(q, `SELECT id, payload FROM xray_installs ORDER BY id`, state.XrayInstalls); err != nil {
		return State{}, err
	}
	rows, err := q.Query(`SELECT payload FROM audit_logs ORDER BY event_seq`)
	if err != nil {
		return State{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		var event Audit
		if err := rows.Scan(&payload); err != nil {
			return State{}, err
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return State{}, err
		}
		state.Audits = append(state.Audits, event)
	}
	return state, rows.Err()
}

func loadMap[T any](q executor, query string, destination map[string]T) error {
	rows, err := q.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var payload []byte
		var value T
		if err := rows.Scan(&key, &payload); err != nil {
			return err
		}
		if err := json.Unmarshal(payload, &value); err != nil {
			return err
		}
		destination[key] = value
	}
	return rows.Err()
}

func persistState(tx *sql.Tx, state State) error {
	for _, table := range []string{"sessions", "nodes", "admins", "audit_logs", "xray_installs"} {
		if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
			return err
		}
	}
	for _, id := range sortedKeys(state.Admins) {
		value := state.Admins[id]
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO admins(id, username, role, disabled, payload) VALUES(?, ?, ?, ?, ?)`, id, value.Username, value.Role, value.Disabled, payload); err != nil {
			return err
		}
	}
	for _, id := range sortedKeys(state.Nodes) {
		value := state.Nodes[id]
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO nodes(id, node_group, last_seen, disabled, payload) VALUES(?, ?, ?, ?, ?)`, id, value.Group, value.LastSeen, value.Disabled, payload); err != nil {
			return err
		}
	}
	for _, id := range sortedKeys(state.Sessions) {
		value := state.Sessions[id]
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO sessions(id_hash, admin_id, created_at, last_seen, expires_at, payload) VALUES(?, ?, ?, ?, ?, ?)`, id, value.AdminID, value.CreatedAt, value.LastSeen, value.ExpiresAt, payload); err != nil {
			return err
		}
	}
	for _, value := range state.Audits {
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO audit_logs(at, actor, resource_type, resource, action, outcome, payload) VALUES(?, ?, ?, ?, ?, ?, ?)`, value.At, value.Actor, value.ResourceType, value.Resource, value.Action, value.Outcome, payload); err != nil {
			return err
		}
	}
	for _, id := range sortedKeys(state.XrayInstalls) {
		payload, err := json.Marshal(state.XrayInstalls[id])
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO xray_installs(id, payload) VALUES(?, ?)`, id, payload); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[T any](items map[string]T) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) Update(fn func(*State) error) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			result = errors.Join(result, fmt.Errorf("roll back panel transaction: %w", err))
		}
	}()
	state, err := loadState(tx)
	if err != nil {
		return err
	}
	if err := fn(&state); err != nil {
		return err
	}
	if err := persistState(tx, state); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		// A failed SQLite COMMIT can leave its transaction open. Never let a
		// checkpoint hash uncommitted state from that same connection.
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		return err
	}
	return nil
}

func (s *Store) View(fn func(State) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, err := loadState(s.db)
	if err != nil {
		return err
	}
	return fn(state)
}

func (s *Store) Close() error { return s.db.Close() }
