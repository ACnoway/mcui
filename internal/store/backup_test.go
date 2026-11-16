package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
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
