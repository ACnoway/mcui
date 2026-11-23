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

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const inboundPolicyPath = "/etc/mcui-xray/controlled-inbound.json"
const catalogFilename = "managed-inbounds.json"

func (s selection) validConfig() bool {
	if s.Config == (xrayconfig.Reference{}) {
		return s.Revision == 0
	}
	return runtime.GOARCH == xrayconfig.Architecture && s.Release.Version == xrayconfig.Version &&
		s.Revision > 0 && s.Revision <= (1<<53)-1 && s.Config.Valid()
}

func (r *Runtime) Inventory(state Status, encoded string, managed bool) lifecycleauth.XrayInventory {
	current := state.Current
	view := lifecycleauth.XrayInventory{
		Version: current.Release.Version, SHA256: current.Release.SHA256, Running: current.Running,
		Config: current.Config, ConfigRevision: current.Revision, PlanSupported: managed,
	}
	catalog, err := readCatalog(inboundPolicyPath, current.Release)
	switch {
	case errors.Is(err, os.ErrNotExist):
		_, view.Candidate, _ = readInbound(inboundPolicyPath, current.Release)
	case err == nil && managed:
		public, _ := catalog.Public(current.Release.SHA256)
		view.Catalog = &public
		if plan, err := xrayconfig.ParsePlan(encoded); err == nil {
			_, view.Candidate, _ = catalog.Render(current.Release.SHA256, plan)
			view.Preview = xrayconfig.PlanDigest(encoded)
		}
	}
	if !managed || current.Revision == 0 {
		return view
	}
	if data, err := r.savedConfig(current.Config); err == nil {
		var config struct {
			Inbounds []struct {
				Port     int `json:"port"`
				Settings struct {
					Users []struct {
						User string `json:"user"`
					} `json:"users"`
				} `json:"settings"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(data, &config) == nil {
			plan := make(xrayconfig.Plan, 0, len(config.Inbounds))
			for _, in := range config.Inbounds {
				entry := xrayconfig.Inbound{Port: in.Port}
				for _, user := range in.Settings.Users {
					entry.Users = append(entry.Users, user.User)
				}
				plan = append(plan, entry)
			}
			if plan.Valid() {
				view.Applied = &plan
			}
		}
	}
	return view
}

func checkPolicyDirectory(path string, release Release) error {
	if runtime.GOARCH != xrayconfig.Architecture || release.Version != xrayconfig.Version || !release.valid() {
		return errors.New("Xray release has no approved inbound template")
	}
	return ownDirectory(filepath.Dir(path), 0700, false)
}

func readCatalog(path string, release Release) (xrayconfig.LocalCatalog, error) {
	var catalog xrayconfig.LocalCatalog
	if err := checkPolicyDirectory(path, release); err != nil {
		return catalog, err
	}
	if err := readJSON(filepath.Join(filepath.Dir(path), catalogFilename), 0600, &catalog); err != nil {
		return catalog, err
	}
	_, err := catalog.Public(release.SHA256)
	return catalog, err
}

func readInbound(path string, release Release) ([]byte, xrayconfig.Reference, error) {
	if err := checkPolicyDirectory(path, release); err != nil {
		return nil, xrayconfig.Reference{}, err
	}
	var policy xrayconfig.Policy
	if err := readJSON(path, 0600, &policy); err != nil {
		return nil, xrayconfig.Reference{}, err
	}
	return policy.Render(release.SHA256)
}

func readCandidate(path string, release Release, encoded string) ([]byte, xrayconfig.Reference, error) {
	catalog, err := readCatalog(path, release)
	if encoded == "" && errors.Is(err, os.ErrNotExist) {
		return readInbound(path, release)
	}
	plan, planErr := xrayconfig.ParsePlan(encoded)
	if err != nil || planErr != nil {
		return nil, xrayconfig.Reference{}, errors.New("node-local Xray catalog or plan is unavailable")
	}
	return catalog.Render(release.SHA256, plan)
}

func (r *Runtime) ConfigureAuthorized(ctx context.Context, release Release, ref xrayconfig.Reference, encoded string, revision int64, hash string, authorize func(context.Context) error) (string, error) {
	return taskOutcome(r.configure(ctx, inboundPolicyPath, release, ref, encoded, revision, hash, authorize))
}

func (r *Runtime) configure(ctx context.Context, path string, release Release, ref xrayconfig.Reference, encoded string, revision int64, hash string, authorize func(context.Context) error) error {
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
	data, candidate, err := readCandidate(path, release, encoded)
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
	_, candidate, err = readCandidate(path, release, encoded)
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
		Inbounds []json.RawMessage `json:"inbounds"`
		Routing  struct {
			Rules []struct {
				IP []string `json:"ip"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(data, &config) != nil {
		return errors.New("invalid saved Xray configuration")
	}
	if config.Inbounds != nil && len(config.Inbounds) == 0 && len(config.Routing.Rules) == 0 {
		return svc.checkConfigUnits(ctx, "")
	}
	if len(config.Inbounds) == 0 || len(config.Routing.Rules) != 1 || len(config.Routing.Rules[0].IP) != 1 {
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
		raw, err := r.savedConfig(next.Config)
		if err != nil {
			return err
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

func (r *Runtime) savedConfig(ref xrayconfig.Reference) ([]byte, error) {
	file, err := checkedFile(filepath.Join(r.dir, "control", configName(ref)), 0600, xrayconfig.MaxSize)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, xrayconfig.MaxSize+1))
	if err != nil || !ref.Matches(raw) {
		return nil, errors.New("saved Xray configuration failed its integrity check")
	}
	return raw, nil
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
