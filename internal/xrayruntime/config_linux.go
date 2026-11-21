//go:build linux

package xrayruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const inboundPolicyPath = "/etc/mcui-xray/controlled-inbound.json"

func (s selection) validConfig() bool {
	if s.Config == (xrayconfig.Reference{}) {
		return s.Revision == 0
	}
	return runtime.GOARCH == xrayconfig.Architecture && s.Release.Version == xrayconfig.Version &&
		s.Revision > 0 && s.Revision <= (1<<53)-1 && s.Config.Valid()
}

func (r *Runtime) ConfigCandidate(state Status) xrayconfig.Reference {
	_, ref, _ := readInbound(inboundPolicyPath, state.Current.Release)
	return ref
}

func readInbound(path string, release Release) ([]byte, xrayconfig.Reference, error) {
	if runtime.GOARCH != xrayconfig.Architecture || release.Version != xrayconfig.Version || !release.valid() {
		return nil, xrayconfig.Reference{}, errors.New("Xray release has no approved inbound template")
	}
	if err := ownDirectory(filepath.Dir(path), 0700, false); err != nil {
		return nil, xrayconfig.Reference{}, err
	}
	var policy xrayconfig.Policy
	if err := readJSON(path, 0600, &policy); err != nil {
		return nil, xrayconfig.Reference{}, err
	}
	return policy.Render(release.SHA256)
}

func (r *Runtime) ConfigureAuthorized(ctx context.Context, release Release, ref xrayconfig.Reference, revision int64, hash string, authorize func(context.Context) error) (string, error) {
	return taskOutcome(r.configure(ctx, inboundPolicyPath, release, ref, revision, hash, authorize))
}

func (r *Runtime) configure(ctx context.Context, path string, release Release, ref xrayconfig.Reference, revision int64, hash string, authorize func(context.Context) error) error {
	if authorize == nil || !ref.Valid() || !validTaskHash(hash) || revision <= 0 || revision > (1<<53)-1 {
		return errors.New("invalid Xray configuration authorization")
	}
	state, err := r.ready()
	if err != nil {
		return errors.Join(errUnknown, err)
	}
	if state.Current.Release != release || revision <= state.ConfigRevision {
		return errors.New("Xray release or configuration revision changed")
	}
	data, candidate, err := readInbound(path, release)
	if err != nil || candidate != ref {
		return errors.New("local Xray configuration differs from the approved reference")
	}
	if err := r.verifyBundle(release); err != nil {
		return err
	}
	if err := r.checkConfigUnits(ctx, data); err != nil {
		return err
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	if err := r.preflightConfig(ctx, release, data); err != nil {
		return err
	}
	if err := r.writeControl(configName(ref), data); err != nil {
		return err
	}
	_, candidate, err = readInbound(path, release)
	if err != nil || candidate != ref {
		return errors.New("local Xray configuration changed during preflight")
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	next := state.Current
	next.Config, next.Revision = ref, revision
	return r.change(ctx, state, intent{Action: Configure, Next: next, ConfigHash: hash})
}

func (r *Runtime) checkConfigUnits(ctx context.Context, data []byte) error {
	svc, ok := r.service.(interface {
		checkConfigUnits(context.Context, string) error
	})
	if !ok {
		return errors.New("Xray service does not support isolated configuration")
	}
	var config struct {
		Routing struct {
			Rules []struct {
				IP []string `json:"ip"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(data, &config) != nil || len(config.Routing.Rules) != 1 || len(config.Routing.Rules[0].IP) != 1 {
		return errors.New("invalid saved Xray route")
	}
	return svc.checkConfigUnits(ctx, config.Routing.Rules[0].IP[0])
}

func (r *Runtime) prepareRuntimeConfig(ctx context.Context, next selection) error {
	if next.Release == (Release{}) {
		return r.removeControl("runtime-config.json")
	}
	data := []byte(bootstrapConfig)
	if next.Revision != 0 {
		file, err := checkedFile(filepath.Join(r.dir, "control", configName(next.Config)), 0600, xrayconfig.MaxSize)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(file, xrayconfig.MaxSize+1))
		file.Close()
		if err != nil || !next.Config.Matches(raw) {
			return errors.New("saved Xray configuration failed its integrity check")
		}
		if next.Running {
			if err := r.checkConfigUnits(ctx, raw); err != nil {
				return err
			}
		}
		data = raw
	}
	return r.writeControl("runtime-config.json", data)
}

func configName(ref xrayconfig.Reference) string {
	return "inbound-" + ref.SHA256 + ".json"
}

func (r *Runtime) removeControl(name string) error {
	dir := filepath.Join(r.dir, "control")
	if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

func (r *Runtime) pruneConfigs(state Status) error {
	dir := filepath.Join(r.dir, "control")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == configName(state.Current.Config) || (state.Pending != nil && name == configName(state.Pending.Next.Config)) {
			continue
		}
		if strings.HasPrefix(name, ".write-") || (strings.HasPrefix(name, "inbound-") && strings.HasSuffix(name, ".json")) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	return syncDir(dir)
}
