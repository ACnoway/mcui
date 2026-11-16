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
		if state.Admins["a1"].Username != "root" || !state.Nodes["node-old"].NeedsReenrollment {
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

func TestLegacyBearerNodesRequireCertificateReenrollment(t *testing.T) {
	legacy := []byte(`{"Nodes":{"node-old":{"id":"node-old","name":"legacy","group":"g1","token_hash":"old-token-hash"}}}`)
	state, err := decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Nodes["node-old"].NeedsReenrollment {
		t.Fatal("legacy bearer node must be marked for mTLS reenrollment")
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
