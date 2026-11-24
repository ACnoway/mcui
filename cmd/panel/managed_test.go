package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedKeysPersistAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	status, core, err := managedKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Equal(core) {
		t.Fatal("signing purposes share a key")
	}
	statusAgain, coreAgain, err := managedKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Equal(statusAgain) || !core.Equal(coreAgain) {
		t.Fatal("signing identity changed after reopening")
	}
	if err := os.WriteFile(filepath.Join(dir, "tasks.db"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "signing-seeds")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := managedKeys(dir); err == nil {
		t.Fatal("generated new keys for an existing runtime")
	}
}
