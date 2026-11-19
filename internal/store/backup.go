package store

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"
)

// Backup writes a consistent SQLite snapshot to a new, owner-only file.
// The destination must not already exist.
func Backup(source, destination string) (err error) {
	sourcePath, err := existingDatabasePath(source)
	if err != nil {
		return err
	}
	destinationPath, parent, err := newDatabasePath(destination)
	if err != nil {
		return err
	}
	if securePathEqual(sourcePath, destinationPath) {
		return errors.New("backup source and destination must differ")
	}
	tmpDir, err := os.MkdirTemp(parent, ".mcui-backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0700); err != nil {
		return err
	}
	tmpPath := filepath.Join(tmpDir, "snapshot.db")
	db, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	if _, err := db.Exec(`VACUUM INTO ?`, tmpPath); err != nil {
		return fmt.Errorf("create SQLite snapshot: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return err
	}
	if _, err := VerifyDatabase(tmpPath); err != nil {
		return fmt.Errorf("verify SQLite snapshot: %w", err)
	}
	if err := syncFile(tmpPath); err != nil {
		return err
	}
	if err := publishFile(tmpPath, destinationPath); err != nil {
		return fmt.Errorf("publish backup without replacing existing file: %w", err)
	}
	return syncDir(parent)
}

// VerifyDatabase checks that a database is a regular, non-symlink SQLite file,
// passes integrity_check, and has a schema version supported by this binary.
func VerifyDatabase(path string) (int, error) {
	databasePath, err := existingDatabasePath(path)
	if err != nil {
		return 0, err
	}
	dsn := "file:" + filepath.ToSlash(databasePath) + "?mode=ro"
	if runtime.GOOS == "windows" {
		// modernc.org/sqlite accepts native Windows paths more reliably than a
		// file: URI. query_only preserves read-only behavior for this path.
		dsn = databasePath
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA query_only=ON`); err != nil {
		return 0, err
	}
	rows, err := db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return 0, fmt.Errorf("SQLite integrity check: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return 0, err
		}
		count++
		if result != "ok" {
			return 0, fmt.Errorf("SQLite integrity check failed: %s", result)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, errors.New("SQLite integrity check returned an unexpected result")
	}
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read database schema version: %w", err)
	}
	if version < 1 || version > schemaVersion {
		return version, fmt.Errorf("database schema version %d is not supported (versions 1 through %d)", version, schemaVersion)
	}
	if err := validateSchema(db, version); err != nil {
		return version, err
	}
	return version, nil
}

func validateSchema(db *sql.DB, version int) error {
	expectedTables := map[string][]string{
		"schema_migrations": {"version", "applied_at"},
		"admins":            {"id", "username", "role", "disabled", "payload"},

		"nodes":    {"id", "node_group", "last_seen", "disabled", "payload"},
		"sessions": {"id_hash", "admin_id", "created_at", "last_seen", "expires_at", "payload"},

		"audit_logs": {"event_seq", "at", "actor", "resource_type", "resource", "action", "outcome", "payload"},
	}
	expectedIndexes := map[string]struct{}{
		"nodes_group_seen_idx": {}, "sessions_admin_idx": {}, "audit_resource_idx": {},
	}
	if version == 1 {
		expectedTables["invites"] = []string{"token_hash", "node_group", "expires_at", "used", "payload"}
		expectedTables["enrollments"] = []string{"request_id", "node_id", "created_at", "payload"}
		expectedIndexes["invites_expiry_idx"] = struct{}{}
	}
	if version >= 3 {
		expectedTables["xray_installs"] = []string{"id", "payload"}
	}
	for table, expected := range expectedTables {
		rows, err := db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			return err
		}
		var columns []string
		for rows.Next() {
			var cid, notNull, primaryKey int
			var name, dataType string
			var defaultValue any
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				return err
			}
			columns = append(columns, name)
		}
		rowsErr := rows.Err()
		_ = rows.Close()
		if rowsErr != nil {
			return rowsErr
		}
		if len(columns) != len(expected) {
			return fmt.Errorf("database table %s has an unexpected column set", table)
		}
		for i := range expected {
			if columns[i] != expected[i] {
				return fmt.Errorf("database table %s has an unexpected column set", table)
			}
		}
	}
	rows, err := db.Query(`SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY type, name`)
	if err != nil {
		return err
	}
	seenTables := map[string]bool{}
	seenIndexes := map[string]bool{}
	for rows.Next() {
		var objectType, name string
		if err := rows.Scan(&objectType, &name); err != nil {
			_ = rows.Close()
			return err
		}
		switch objectType {
		case "table":
			if _, ok := expectedTables[name]; !ok {
				_ = rows.Close()
				return fmt.Errorf("database contains unexpected table %s", name)
			}
			seenTables[name] = true
		case "index":
			if _, ok := expectedIndexes[name]; !ok {
				_ = rows.Close()
				return fmt.Errorf("database contains unexpected index %s", name)
			}
			seenIndexes[name] = true
		default:
			_ = rows.Close()
			return fmt.Errorf("database contains unexpected SQLite object %s", name)
		}
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		return rowsErr
	}
	if len(seenTables) != len(expectedTables) || len(seenIndexes) != len(expectedIndexes) {
		return errors.New("database schema is incomplete")
	}
	return nil
}

// Restore copies a verified backup into a new owner-only restore candidate.
// It never replaces the live database or an existing destination.
func Restore(backup, destination string) (err error) {
	sourcePath, err := existingDatabasePath(backup)
	if err != nil {
		return err
	}
	if _, err := VerifyDatabase(sourcePath); err != nil {
		return fmt.Errorf("verify restore source: %w", err)
	}
	destinationPath, parent, err := newDatabasePath(destination)
	if err != nil {
		return err
	}
	if securePathEqual(sourcePath, destinationPath) {
		return errors.New("restore source and destination must differ")
	}
	tmpDir, err := os.MkdirTemp(parent, ".mcui-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0700); err != nil {
		return err
	}
	tmpPath := filepath.Join(tmpDir, "candidate.db")
	if err := copyOwnerOnly(sourcePath, tmpPath); err != nil {
		return err
	}
	if _, err := VerifyDatabase(tmpPath); err != nil {
		return fmt.Errorf("verify restore candidate: %w", err)
	}
	if err := publishFile(tmpPath, destinationPath); err != nil {
		return fmt.Errorf("publish restore candidate without replacing existing file: %w", err)
	}
	return syncDir(parent)
}

func existingDatabasePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() == 0 {
		return "", errors.New("database path must be a non-empty regular file, not a symlink")
	}
	return filepath.Clean(absolute), nil
}

func newDatabasePath(path string) (string, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	absolute = filepath.Clean(absolute)
	parent := filepath.Dir(absolute)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return "", "", err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return "", "", errors.New("database destination parent must be a real directory")
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", "", errors.New("database destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	return absolute, parent, nil
}

func copyOwnerOnly(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func publishFile(source, destination string) error {
	if runtime.GOOS == "windows" {
		return copyOwnerOnly(source, destination)
	}
	return os.Link(source, destination)
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func securePathEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
