package artifacttrust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// OpenLocalManifest reads an operator-deployed copy of the signed release
// manifest. The initialized rollback state belongs to the signing account.
func OpenLocalManifest(stateDir, keyPath, manifestPath, signaturePath string, now func() (time.Time, error), keyAllowed func(ed25519.PublicKey) bool) (func(context.Context) (Manifest, error), error) {
	if !filepath.IsAbs(stateDir) || !filepath.IsAbs(manifestPath) || !filepath.IsAbs(signaturePath) || now == nil {
		return nil, ErrUnavailable
	}
	key, err := readProvisionedManifestKey(keyPath)
	if err != nil {
		return nil, err
	}
	if keyAllowed != nil && !keyAllowed(key) {
		return nil, errors.New("release and task authorization keys must differ")
	}
	return func(ctx context.Context) (Manifest, error) {
		unlock, err := lockManifestState(stateDir)
		if err != nil {
			return Manifest{}, err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(stateDir, manifestSuspendedName)); !errors.Is(err, os.ErrNotExist) {
			return Manifest{}, ErrUnavailable
		}
		prior, err := readManifestState(stateDir)
		if err != nil {
			return Manifest{}, err
		}
		raw, err := readLocalManifestPart(manifestPath, MaxManifestBytes)
		if err != nil {
			return Manifest{}, err
		}
		sig, err := readLocalManifestPart(signaturePath, ed25519.SignatureSize)
		if err != nil {
			return Manifest{}, err
		}
		at, err := now()
		if err != nil {
			return Manifest{}, err
		}
		manifest, err := VerifyManifest(raw, sig, key, at)
		if err != nil {
			return Manifest{}, err
		}
		if err := ctx.Err(); err != nil {
			return Manifest{}, err
		}
		return manifest, advanceManifestState(stateDir, prior, stateOf(manifest, raw))
	}, nil
}

func readLocalManifestPart(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, ErrUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, ErrUnavailable
	}
	return raw, nil
}
