//go:build linux

package runtimeupdate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/checkedasset"
)

func (m *Manager) stageArchive(ctx context.Context, artifact artifacttrust.Artifact) (Pair, error) {
	return m.stageArchiveFile(ctx, artifact, filepath.Join(m.dir, "incoming", artifact.Filename))
}

func (m *Manager) stageArchiveFile(ctx context.Context, artifact artifacttrust.Artifact, path string) (Pair, error) {
	if artifact.Architecture != runtime.GOARCH || artifact.Length > MaxArchive {
		return Pair{}, errors.New("runtime archive architecture or size rejected")
	}
	file, size, err := openTrusted(path, MaxArchive)
	if err != nil {
		return Pair{}, err
	}
	defer file.Close()
	if size != artifact.Length {
		return Pair{}, errors.New("runtime archive length does not match manifest")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, size+1))
	if err != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return Pair{}, errors.New("runtime archive digest or length rejected")
	}
	if err := checkedasset.ZIP32Directory(file, size, 2, 2); err != nil {
		return Pair{}, err
	}
	archive, err := zip.NewReader(file, size)
	if err != nil {
		return Pair{}, err
	}
	entries := make(map[string]*zip.File, len(archive.File))
	for _, entry := range archive.File {
		if (entry.Name != agentBinary && entry.Name != helperBinary) || entries[entry.Name] != nil ||
			entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > maxBinary || !entry.Mode().IsRegular() ||
			entry.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || entry.Flags&1 != 0 ||
			(entry.Method != zip.Store && entry.Method != zip.Deflate) {
			return Pair{}, errors.New("invalid runtime ZIP member")
		}
		entries[entry.Name] = entry
	}
	if len(entries) != len(binaries) {
		return Pair{}, errors.New("runtime ZIP must contain exactly the Agent and Helper")
	}
	return m.stagePair(ctx, artifact.Version, func(name string) (io.ReadCloser, int64, error) {
		entry := entries[name]
		reader, err := entry.Open()
		return reader, int64(entry.UncompressedSize64), err
	})
}

func (m *Manager) stagePair(ctx context.Context, version string, open func(string) (io.ReadCloser, int64, error)) (Pair, error) {
	stage, err := os.MkdirTemp(filepath.Join(m.dir, "releases"), ".stage-")
	if err != nil {
		return Pair{}, err
	}
	defer func() {
		_ = os.Chmod(stage, 0700)
		_ = os.RemoveAll(stage)
	}()
	var digests [len(binaries)]string
	for i, name := range binaries {
		reader, size, err := open(name)
		if err != nil {
			return Pair{}, err
		}
		digests[i], err = stageBinary(ctx, filepath.Join(stage, name), reader, size)
		if err = errors.Join(err, reader.Close()); err != nil {
			return Pair{}, err
		}
	}
	pair := Pair{Version: version, AgentSHA256: digests[0], HelperSHA256: digests[1]}
	dest := filepath.Join(m.dir, "releases", pair.Digest())
	if _, err := os.Lstat(dest); err == nil {
		if err := m.verifyPair(pair); err != nil {
			return Pair{}, err
		}
		return pair, syncDir(filepath.Dir(dest))
	} else if !errors.Is(err, os.ErrNotExist) {
		return Pair{}, err
	}
	if err := os.Chmod(stage, 0555); err != nil {
		return Pair{}, err
	}
	if err := syncDir(stage); err != nil {
		return Pair{}, err
	}
	if err := os.Rename(stage, dest); err != nil {
		return Pair{}, err
	}
	return pair, syncDir(filepath.Dir(dest))
}

func stageBinary(ctx context.Context, path string, reader io.Reader, size int64) (string, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(contextReader{ctx, reader}, size+1))
	if err != nil || n != size {
		return "", fmt.Errorf("runtime binary length or checksum rejected: %s", filepath.Base(path))
	}
	if err := checkedasset.LinuxExecutable(file, runtime.GOARCH); err != nil {
		return "", err
	}
	if err := file.Chmod(0555); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}
