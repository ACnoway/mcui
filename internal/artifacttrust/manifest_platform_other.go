//go:build !linux

package artifacttrust

import "crypto/ed25519"

func lockManifestState(string) (func(), error) { return nil, ErrUnavailable }

func readProvisionedManifestKey(string) (ed25519.PublicKey, error) { return nil, ErrUnavailable }
