package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("record not found")

type State struct {
	Admins   map[string]Admin   `json:"admins"`
	Invites  map[string]Invite  `json:"invites"`
	Nodes    map[string]Node    `json:"nodes"`
	Sessions map[string]Session `json:"sessions"`
	Audits   []Audit            `json:"audits"`
}
type Admin struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	TOTPSecret   string `json:"totp_secret"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
}
type Invite struct {
	Hash      string `json:"hash"`
	NodeGroup string `json:"node_group"`
	ExpiresAt int64  `json:"expires_at"`
	Used      bool   `json:"used"`
}
type Node struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Group         string `json:"group"`
	PublicKey     string `json:"public_key"`
	TokenHash     string `json:"token_hash,omitempty"`
	Certificate   string `json:"certificate,omitempty"`
	LastSeen      int64  `json:"last_seen"`
	Disabled      bool   `json:"disabled"`
	RevokedSerial string `json:"revoked_serial,omitempty"`
}
type Session struct {
	ID        string `json:"id"`
	AdminID   string `json:"admin_id"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}
type Audit struct {
	At       int64  `json:"at"`
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Outcome  string `json:"outcome"`
}
type Store struct {
	mu sync.RWMutex
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL)", "INSERT OR IGNORE INTO app_state(id,payload) VALUES(1,'{}')"} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	s := &Store{db: db}
	if e = s.Update(func(st *State) error { return nil }); e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func emptyState() State {
	return State{Admins: map[string]Admin{}, Invites: map[string]Invite{}, Nodes: map[string]Node{}, Sessions: map[string]Session{}, Audits: []Audit{}}
}
func decode(b []byte) (State, error) {
	s := emptyState()
	if string(b) == "{}" {
		return s, nil
	}
	if e := json.Unmarshal(b, &s); e != nil {
		return State{}, e
	}
	if s.Admins == nil {
		s.Admins = map[string]Admin{}
	}
	if s.Invites == nil {
		s.Invites = map[string]Invite{}
	}
	if s.Nodes == nil {
		s.Nodes = map[string]Node{}
	}
	if s.Sessions == nil {
		s.Sessions = map[string]Session{}
	}
	if s.Audits == nil {
		s.Audits = []Audit{}
	}
	return s, nil
}
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var b []byte
	if e = tx.QueryRow("SELECT payload FROM app_state WHERE id=1").Scan(&b); e != nil {
		return e
	}
	st, e := decode(b)
	if e != nil {
		return e
	}
	if e = fn(&st); e != nil {
		return e
	}
	b, e = json.Marshal(st)
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE app_state SET payload=? WHERE id=1", b); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) View(fn func(State) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var b []byte
	if e := s.db.QueryRow("SELECT payload FROM app_state WHERE id=1").Scan(&b); e != nil {
		return e
	}
	st, e := decode(b)
	if e != nil {
		return e
	}
	return fn(st)
}
func (s *Store) Close() error { return s.db.Close() }
