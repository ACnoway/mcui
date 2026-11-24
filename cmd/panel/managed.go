package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/master"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/tasksigner"
	"github.com/ACnoway/mcui/internal/trustedtime"
)

func configureManagedRuntime(srv *master.Server, dataDir, releaseDir, publicURL, caPath string, https bool) (func(), error) {
	dir, err := filepath.Abs(filepath.Join(dataDir, "managed"))
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		return nil, errors.New("managed state requires a private directory")
	}
	statusKey, coreKey, err := managedKeys(dir)
	if err != nil {
		return nil, err
	}
	statusPublic := statusKey.Public().(ed25519.PublicKey)
	corePublic := coreKey.Public().(ed25519.PublicKey)
	statusID := managedKeyID("status", statusPublic)
	coreID := managedKeyID("core", corePublic)
	statusSigner, err := tasksigner.New(statusID, statusKey)
	if err != nil {
		return nil, err
	}
	clock := trustedtime.NewChronyUnix(trustedtime.DefaultNTSSource)
	taskRuntime := master.TaskRuntime{Signer: statusSigner, KeyID: statusID, PublicKey: statusPublic, TrustedNow: clock.Now}

	var coreSigner *lifecycleauth.PanelSigner
	closeCore := func() {}
	release, err := os.ReadFile(filepath.Join(releaseDir, "agent-release"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(release) != 0 {
		fields := strings.Fields(string(release))
		if len(fields) != 2 {
			return nil, errors.New("packaged Agent release needs a tag and an installer SHA-256")
		}
		if https {
			var ca []byte
			if caPath != "" {
				ca, err = security.ReadEnrollmentCA(caPath)
				if err != nil {
					return nil, err
				}
			}
			if err := srv.ConfigureGitHubAgentInstaller(publicURL, fields[0], fields[1], statusID, statusPublic, coreID, corePublic, ca); err != nil {
				return nil, err
			}
		}
		policy, err := lifecycleauth.NewSingleAdminPolicy(coreID, corePublic)
		if err != nil {
			return nil, err
		}
		source, err := artifacttrust.OpenPublishedManifest(filepath.Join(releaseDir, "release.pub"), filepath.Join(dir, "manifest"), clock.Now, statusPublic, corePublic)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, "core-issuance.db")
		if err := lifecycleauth.InitLedger(path); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		ledger, err := lifecycleauth.OpenLedger(path)
		if err != nil {
			return nil, err
		}
		coreSigner, err = lifecycleauth.NewPanelSigner(policy, ledger, coreKey, clock.Now, source)
		if err != nil {
			_ = ledger.Close()
			return nil, err
		}
		closeCore = func() { _ = ledger.Close() }
		taskRuntime.XrayInstallPolicy = policy
	} else {
		log.Print("source build has no packaged Agent release; GitHub Agent enrollment and Core management are unavailable")
	}
	tasks, err := openTaskStore(filepath.Join(dir, "tasks.db"), true)
	if err != nil {
		closeCore()
		return nil, err
	}
	closeRuntime := func() {
		_ = tasks.Close()
		closeCore()
	}
	taskRuntime.Store = tasks
	if err = srv.ConfigureTaskRuntime(taskRuntime); err == nil && coreSigner != nil {
		err = srv.ConfigurePanelXray(coreSigner)
	}
	if err == nil {
		err = srv.ReconcileTaskRuntime()
	}
	if err != nil {
		closeRuntime()
		return nil, err
	}
	log.Print("managed task runtime enabled")
	return closeRuntime, nil
}

func managedKeyID(purpose string, key ed25519.PublicKey) string {
	hash := sha256.Sum256(key)
	return fmt.Sprintf("%s-%x", purpose, hash[:12])
}

func managedKeys(dir string) (ed25519.PrivateKey, ed25519.PrivateKey, error) {
	path := filepath.Join(dir, "signing-seeds")
	seeds, err := readPrivateKey(path)
	if errors.Is(err, os.ErrNotExist) {
		for _, name := range []string{"tasks.db", "core-issuance.db", "manifest"} {
			if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
				return nil, nil, errors.New("managed signing keys are missing from existing state; restore the volume backup")
			}
		}
		if err := createManagedSeeds(dir, path); err != nil {
			return nil, nil, err
		}
		seeds, err = readPrivateKey(path)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(seeds) != 2*ed25519.SeedSize {
		return nil, nil, errors.New("managed signing seeds are damaged")
	}
	return ed25519.NewKeyFromSeed(seeds[:ed25519.SeedSize]), ed25519.NewKeyFromSeed(seeds[ed25519.SeedSize:]), nil
}

func createManagedSeeds(dir, path string) error {
	var seeds [2 * ed25519.SeedSize]byte
	if _, err := rand.Read(seeds[:]); err != nil {
		return err
	}
	staged, err := os.CreateTemp(dir, ".signing-seeds-")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err = staged.Write(seeds[:]); err == nil {
		err = staged.Sync()
	}
	if err = errors.Join(err, staged.Close()); err != nil {
		return err
	}
	if err := os.Link(staged.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
