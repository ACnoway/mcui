package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/tufrepo"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

type generation struct {
	files    map[string][]byte
	versions map[string]int64
}

func assemble(rootPath, source, previous, destination string) error {
	if source == "" {
		return errors.New("signed metadata directory is required")
	}
	bootstrap, err := readRegular(rootPath, 512<<10, false)
	if err != nil {
		return err
	}
	release, err := verifyGeneration(bootstrap, source, false, time.Now().UTC())
	if err != nil {
		return err
	}
	if previous != "" {
		old, err := verifyGeneration(bootstrap, previous, true, time.Unix(0, 0).UTC())
		if err != nil {
			return fmt.Errorf("verify previous published generation: %w", err)
		}
		if err := release.follows(old); err != nil {
			return err
		}
	} else {
		for role, version := range release.versions {
			if version != 1 {
				return fmt.Errorf("publishing %s version %d requires the prior generation", role, version)
			}
		}
	}
	return release.write(destination)
}

func verifyGeneration(bootstrap []byte, dir string, published bool, now time.Time) (generation, error) {
	release := generation{files: map[string][]byte{}, versions: map[string]int64{}}
	trusted, err := trustedmetadata.New(bootstrap)
	if err != nil {
		return release, err
	}
	if trusted.Root.Signed.Version != 1 {
		return release, errors.New("assemble requires the repository's original offline root")
	}
	if err := tufrepo.ValidateRootLayout(trusted.Root.Signed); err != nil {
		return release, err
	}
	trusted.RefTime = now
	if err := loadRoots(trusted, &release, dir, bootstrap); err != nil {
		return release, err
	}

	timestampRaw, err := readRegular(filepath.Join(dir, "timestamp.json"), 16<<10, false)
	if err != nil {
		return release, err
	}
	timestamp, err := metadata.Timestamp().FromBytes(timestampRaw)
	if err != nil {
		return release, err
	}
	timestampMeta := timestamp.Signed.Meta["snapshot.json"]
	if timestamp.Signed.Version < 1 || len(timestamp.Signed.Meta) != 1 || !validBinding(timestampMeta, 2<<20) {
		return release, errors.New("timestamp must exactly bind a snapshot")
	}
	if _, err := trusted.UpdateTimestamp(timestampRaw); err != nil {
		return release, err
	}
	release.add(metadata.TIMESTAMP, timestamp.Signed.Version, timestampRaw)
	snapshotRaw, err := readRoleFile(dir, metadata.SNAPSHOT, timestampMeta, published)
	if err != nil {
		return release, err
	}
	snapshot, err := trusted.UpdateSnapshot(snapshotRaw, false)
	if err != nil {
		return release, err
	}
	release.add(metadata.SNAPSHOT, snapshot.Signed.Version, snapshotRaw)
	if len(snapshot.Signed.Meta) != len(targetRoles) {
		return release, errors.New("snapshot must bind all three targets roles")
	}
	for _, name := range targetRoles {
		if err := verifyTargets(trusted, &release, dir, name, published); err != nil {
			return release, fmt.Errorf("verify %s: %w", name, err)
		}
	}
	return release, nil
}

func loadRoots(trusted *trustedmetadata.TrustedMetadata, release *generation, dir string, bootstrap []byte) error {
	const maxRoots = 256
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	roots := map[int64]string{}
	for _, entry := range entries {
		name, rootFile := strings.CutSuffix(entry.Name(), ".root.json")
		if !rootFile {
			continue
		}
		version, err := strconv.ParseInt(name, 10, 64)
		if err != nil || version < 1 || version > maxRoots || strconv.FormatInt(version, 10) != name {
			return errors.New("invalid versioned root filename")
		}
		roots[version] = entry.Name()
	}
	if first := roots[1]; first != "" {
		actual, err := readRegular(filepath.Join(dir, first), 512<<10, false)
		if err != nil || !bytes.Equal(actual, bootstrap) {
			return errors.New("published root 1 differs from the offline bootstrap")
		}
	}
	release.files["1.root.json"] = bootstrap
	delete(roots, 1)
	for version := int64(2); version <= int64(len(roots))+1; version++ {
		filename := roots[version]
		if filename == "" {
			return errors.New("gap in the root rotation chain")
		}
		data, err := readRegular(filepath.Join(dir, filename), 512<<10, false)
		if err != nil {
			return err
		}
		root, err := trusted.UpdateRoot(data)
		if err != nil {
			return err
		}
		if err := tufrepo.ValidateRootLayout(root.Signed); err != nil {
			return err
		}
		release.files[filename] = data
	}
	release.versions[metadata.ROOT] = trusted.Root.Signed.Version
	return nil
}

func verifyTargets(trusted *trustedmetadata.TrustedMetadata, release *generation, dir, name string, published bool) error {
	info := trusted.Snapshot.Signed.Meta[name+".json"]
	if !validBinding(info, maxMetadata) {
		return errors.New("invalid targets metadata binding")
	}
	raw, err := readRoleFile(dir, name, info, published)
	if err != nil {
		return err
	}
	parent := metadata.TARGETS
	if name == metadata.TARGETS {
		parent = metadata.ROOT
	}
	doc, err := trusted.UpdateDelegatedTargets(raw, name, parent)
	if err != nil {
		return err
	}
	release.add(name, doc.Signed.Version, raw)
	if name == metadata.TARGETS {
		return tufrepo.ValidateDelegations(trusted.Root.Signed, doc.Signed)
	}
	if doc.Signed.Delegations != nil {
		return errors.New("release roles must sign targets directly")
	}
	for path, target := range doc.Signed.Targets {
		validate := artifacttrust.ValidateReviewedCoreTarget
		if name == tufrepo.RuntimeRole {
			validate = tufrepo.ValidateRuntimeTarget
		}
		if err := validate(path, target); err != nil {
			return fmt.Errorf("invalid release target %q: %w", path, err)
		}
	}
	return nil
}

func validBinding(info *metadata.MetaFiles, maxBytes int64) bool {
	return info != nil && info.Version > 0 && info.Length > 0 && info.Length <= maxBytes && len(info.Hashes["sha256"]) == 32
}

func readRoleFile(dir, role string, info *metadata.MetaFiles, published bool) ([]byte, error) {
	filename := role + ".json"
	if published {
		filename = roleFilename(role, info.Version)
	}
	return readRegular(filepath.Join(dir, filename), info.Length, false)
}

func roleFilename(role string, version int64) string {
	if role == metadata.TIMESTAMP {
		return "timestamp.json"
	}
	return fmt.Sprintf("%d.%s.json", version, role)
}

func (g generation) add(role string, version int64, data []byte) {
	g.versions[role] = version
	g.files[roleFilename(role, version)] = data
}

func (g generation) follows(previous generation) error {
	for name, past := range previous.versions {
		current := g.versions[name]
		if current < past || (name == metadata.TIMESTAMP && current == past) {
			return fmt.Errorf("publication would reuse or roll back %s version %d", name, past)
		}
		file := roleFilename(name, past)
		if name != metadata.TIMESTAMP && current == past && !bytes.Equal(previous.files[file], g.files[file]) {
			return fmt.Errorf("publication would replace existing metadata file %s", file)
		}
	}
	for version := int64(1); version <= previous.versions[metadata.ROOT]; version++ {
		file := roleFilename(metadata.ROOT, version)
		if !bytes.Equal(previous.files[file], g.files[file]) {
			return fmt.Errorf("publication would replace or remove existing root %d", version)
		}
	}
	return nil
}

func (g generation) write(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("publication output path must be new")
	}
	parent := filepath.Dir(path)
	stage, err := os.MkdirTemp(parent, ".mcui-tuf-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for filename, data := range g.files {
		if err := writeNew(filepath.Join(stage, filename), data); err != nil {
			return err
		}
	}
	if err := os.Chmod(stage, 0755); err != nil {
		return err
	}
	if err := syncDirectory(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
