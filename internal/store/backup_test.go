package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupVerifyAndRestoreCandidate(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "live.db")
	st, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *State) error {
		state.Admins["admin-1"] = Admin{ID: "admin-1", Username: "owner", Role: "security_admin", AllNodes: true}
		state.Nodes["node-1"] = Node{ID: "node-1", Name: "edge-1", Group: "west"}
		state.XrayClients["alice"] = XrayClient{Revision: 2, Bindings: []XrayClientBinding{
			{XrayBinding: XrayBinding{NodeID: "node-1", Port: 1080, Credential: "alice"}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	backup := filepath.Join(root, "snapshot.db")
	if err := Backup(database, backup); err != nil {
		t.Fatal(err)
	}
	if version, err := VerifyDatabase(backup); err != nil || version != schemaVersion {
		t.Fatalf("verify version=%d err=%v", version, err)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("backup permissions are too broad: %o", info.Mode().Perm())
	}

	st, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(state *State) error {
		delete(state.Nodes, "node-1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	candidate := filepath.Join(root, "restored.db")
	if err := Restore(backup, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDatabase(candidate); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(candidate)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.View(func(state State) error {
		if state.Nodes["node-1"].Name != "edge-1" || state.Admins["admin-1"].Username != "owner" {
			t.Fatalf("restore candidate omitted database records: %+v", state)
		}
		if client := state.XrayClients["alice"]; client.Revision != 2 || len(client.Bindings) != 1 || client.Bindings[0].NodeID != "node-1" {
			t.Fatal("restore candidate omitted Xray client bindings")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestBackupAndRestoreNeverReplaceExistingDestination(t *testing.T) {
	root := t.TempDir()
	database := filepath.Join(root, "live.db")
	st, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	backup := filepath.Join(root, "snapshot.db")
	if err := Backup(database, backup); err != nil {
		t.Fatal(err)
	}
	if err := Backup(database, backup); err == nil {
		t.Fatal("backup replaced an existing destination")
	}
	if err := Restore(backup, backup); err == nil {
		t.Fatal("restore accepted its source as destination")
	}
	if err := Restore(backup, database); err == nil {
		t.Fatal("restore replaced the live database")
	}
}

func TestVerifyRejectsCorruptAndNonDatabaseFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDatabase(path); err == nil {
		t.Fatal("corrupt file passed verification")
	}
	if _, err := VerifyDatabase(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Fatal("missing database passed verification")
	}
}

func TestVerifyRejectsHiddenSQLiteLookalikeTrigger(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "modified.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// The normal schema contains SQLite-owned objects such as sqlite_sequence
	// and autoindexes; they must remain accepted.
	if _, err := VerifyDatabase(path); err != nil {
		t.Fatalf("valid database rejected: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER sqlitexevil AFTER INSERT ON admins BEGIN SELECT 1; END`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDatabase(path); err == nil || !strings.Contains(err.Error(), "sqlitexevil") {
		t.Errorf("expected unexpected object error for sqlitexevil, got %v", err)
	}
	backup := filepath.Join(root, "snapshot.db")
	if err := Backup(path, backup); err == nil || !strings.Contains(err.Error(), "sqlitexevil") {
		t.Errorf("expected backup to reject sqlitexevil, got %v", err)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Errorf("rejected backup should not be published: %v", err)
	}
}

func TestVerifyRejectsUnexpectedDatabaseObjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "modified.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER unexpected_trigger AFTER INSERT ON admins BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := VerifyDatabase(path); err == nil {
		t.Fatal("database with an unexpected trigger passed verification")
	}
}
