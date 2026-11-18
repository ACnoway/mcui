package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenMigratesLegacySerializedStateToVersionedTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE app_state (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"Admins":{"a1":{"id":"a1","username":"root","role":"security_admin"}},"Nodes":{"node-old":{"id":"node-old","name":"legacy","group":"g1","token_hash":"old-token-hash"}},"Invites":{},"Sessions":{},"Audits":[]}`)
	if _, err := db.Exec(`INSERT INTO app_state(id, payload) VALUES(1, ?)`, legacy); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if err := opened.View(func(state State) error {
		if state.Admins["a1"].Username != "root" || state.Nodes["node-old"].TokenHash != "" {
			t.Fatalf("legacy data was not migrated safely: %+v", state)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var appStateCount int
	if err := opened.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_state'`).Scan(&appStateCount); err != nil {
		t.Fatal(err)
	}
	if appStateCount != 0 {
		t.Fatal("legacy serialized state table was not removed after migration")
	}
	var version int
	if err := opened.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
}

func TestVersionOneNodeMigrationKeepsInventoryAndDiscardsLegacyCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range append(append([]string(nil), schemaV2...),
		`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`INSERT INTO schema_migrations(version) VALUES(1)`,
		`CREATE TABLE invites(token_hash TEXT PRIMARY KEY, node_group TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL, payload BLOB NOT NULL)`,
		`CREATE INDEX invites_expiry_idx ON invites(used, expires_at)`,
		`CREATE TABLE enrollments(request_id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id), created_at INTEGER NOT NULL, payload BLOB NOT NULL)`,
	) {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	const legacy = `{"id":"node-old","name":"legacy","group":"west","last_seen":42,"current_serial":"123","certificates":{"123":{}},"token_hash":"obsolete"}`
	if _, err := db.Exec("INSERT INTO nodes VALUES(?, ?, ?, ?, ?)", "node-old", "west", 42, false, []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	if version, err := VerifyDatabase(path); err != nil || version != 1 {
		t.Fatalf("v1 verify: version=%d, err=%v", version, err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.View(func(st State) error {
		n := st.Nodes["node-old"]
		if n.ID != "node-old" || n.Name != "legacy" || n.Group != "west" || n.LastSeen != 42 || !n.Enrolled || n.TokenHash != "" {
			return errors.New("migration changed existing identity or carried forward a legacy credential")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.QueryRow("SELECT payload FROM nodes WHERE id='node-old'").Scan(&raw); err != nil ||
		bytes.Contains(raw, []byte("certificates")) || bytes.Contains(raw, []byte("obsolete")) {
		t.Fatalf("v1 credentials were retained: %v", err)
	}
	if version, err := VerifyDatabase(path); err != nil || version != schemaVersion {
		t.Fatalf("migrated verify: version=%d, err=%v", version, err)
	}
}

func TestOpenPersistsAtomicUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Update(func(st *State) error {
		st.Nodes["node-a"] = Node{ID: "node-a", Name: "test"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.View(func(st State) error {
		if got := st.Nodes["node-a"].Name; got != "test" {
			t.Fatalf("node name = %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyBearerNodesRequireNewEnrollment(t *testing.T) {
	legacy := []byte(`{"Nodes":{"node-old":{"id":"node-old","name":"legacy","group":"g1","token_hash":"old-token-hash"}}}`)
	state, err := decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if state.Nodes["node-old"].TokenHash != "" {
		t.Fatal("legacy bearer credential must be discarded")
	}
	normalized, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if string(normalized) == "" || bytes.Contains(normalized, []byte("old-token-hash")) {
		t.Fatal("legacy bearer token hash was retained")
	}
}

func TestFailedUpdateDoesNotCommit(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	wantErr := errors.New("abort")
	if err := s.Update(func(st *State) error { st.Nodes["bad"] = Node{ID: "bad"}; return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("Update error = %v", err)
	}
	if err := s.View(func(st State) error {
		if _, ok := st.Nodes["bad"]; ok {
			t.Fatal("failed transaction was committed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
