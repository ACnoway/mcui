// Package tufrepo defines MCUI's role layout for standard TUF repositories.
package tufrepo

import (
	"errors"
	"fmt"
	"slices"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	CoreRole    = "core-targets"
	RuntimeRole = "runtime-targets"
	CorePath    = "cores/*/*/linux/*/*"
	RuntimePath = "runtime/*/*/linux/*/*"
)

// ValidateRootLayout requires independent keys for every top-level role.
func ValidateRootLayout(root metadata.RootType) error {
	_, err := rootKeys(root)
	return err
}

func rootKeys(root metadata.RootType) (map[string]bool, error) {
	if len(root.Roles) != 4 || !root.ConsistentSnapshot {
		return nil, errors.New("TUF root must declare the four top-level roles and consistent snapshots")
	}
	used := map[string]bool{}
	for _, name := range metadata.TOP_LEVEL_ROLE_NAMES {
		role := root.Roles[name]
		threshold, count := 1, 1
		if name == metadata.ROOT || name == metadata.TARGETS {
			threshold, count = 2, 3
		}
		if role == nil || role.Threshold != threshold || len(role.KeyIDs) != count {
			return nil, fmt.Errorf("invalid threshold or key count for TUF role %s", name)
		}
		if err := addIndependentKeys(used, root.Keys, role.KeyIDs); err != nil {
			return nil, fmt.Errorf("TUF role %s: %w", name, err)
		}
	}
	return used, nil
}

// ValidateDelegations requires the Core and Agent/Helper roles to use disjoint
// signing keys and terminating, non-overlapping paths.
func ValidateDelegations(root metadata.RootType, targets metadata.TargetsType) error {
	used, err := rootKeys(root)
	if err != nil {
		return err
	}
	d := targets.Delegations
	if len(targets.Targets) != 0 || d == nil || d.SuccinctRoles != nil || len(d.Roles) != 2 {
		return errors.New("top-level targets must delegate all artifacts to the two release roles")
	}
	paths := map[string]string{CoreRole: CorePath, RuntimeRole: RuntimePath}
	for _, role := range d.Roles {
		path := paths[role.Name]
		if path == "" || !slices.Equal(role.Paths, []string{path}) || len(role.PathHashPrefixes) != 0 ||
			!role.Terminating || role.Threshold != 2 || len(role.KeyIDs) != 3 {
			return fmt.Errorf("invalid TUF delegation for role %s", role.Name)
		}
		if err := addIndependentKeys(used, d.Keys, role.KeyIDs); err != nil {
			return fmt.Errorf("TUF role %s: %w", role.Name, err)
		}
		delete(paths, role.Name)
	}
	return nil
}

func addIndependentKeys(used map[string]bool, available map[string]*metadata.Key, ids []string) error {
	for _, id := range ids {
		key := available[id]
		if key == nil || key.Type != "ed25519" || key.Scheme != "ed25519" {
			return errors.New("release keys must be Ed25519")
		}
		canonical, err := key.ID()
		if err != nil || canonical != id {
			return errors.New("release key ID does not match the public key")
		}
		if _, err := key.ToPublicKey(); err != nil {
			return errors.New("invalid release public key")
		}
		if used[id] {
			return errors.New("release key is duplicated or shared across roles")
		}
		used[id] = true
	}
	return nil
}
