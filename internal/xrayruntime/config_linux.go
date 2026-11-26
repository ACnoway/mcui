//go:build linux

package xrayruntime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	key, keyErr := r.panelKey()
	var statsGroup uint32
	if keyErr == nil && managed && runtime.GOARCH == xrayconfig.Architecture {
		view.PanelKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		view.PanelMultiClient = true
		view.PanelMultiRoute = true
		statsGroup, view.PanelStatistics = statisticsGroup()
		if network, ok := r.service.(panelNetworkService); ok {
			view.PanelTrojan = true
			view.PanelPublicVLESS = true
			view.PanelAddresses, _ = network.panelAddresses()
		}
		if plan, err := xrayconfig.ParseConfiguration(encoded); err == nil && plan.Panel != nil &&
			(!plan.Panel.Statistics || view.PanelStatistics) && checkPolicyDirectory(inboundPolicyPath, current.Release) == nil {
			_, view.Candidate, _ = plan.RenderPanel(key)
			view.Preview = xrayconfig.PlanDigest(encoded)
		}
	} else if errors.Is(keyErr, os.ErrNotExist) {
		catalog, err := readCatalog(inboundPolicyPath, current.Release)
		switch {
		case errors.Is(err, os.ErrNotExist):
			_, view.Candidate, _ = readInbound(inboundPolicyPath, current.Release)
		case err == nil && managed:
			public, _ := catalog.Public(current.Release.SHA256)
			view.Catalog = &public
			if plan, err := xrayconfig.ParseConfiguration(encoded); err == nil {
				_, view.Candidate, _ = catalog.RenderConfiguration(current.Release.SHA256, plan)
				view.Preview = xrayconfig.PlanDigest(encoded)
			}
		}
	}
	if !managed || current.Revision == 0 {
		return view
	}
	if data, err := r.savedConfig(current.Config); err == nil {
		var config struct {
			Stats    json.RawMessage `json:"stats"`
			Inbounds []struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				Listen   string `json:"listen"`
				Tag      string `json:"tag"`
				Settings struct {
					Users []struct {
						User string `json:"user"`
						Name string `json:"email"`
						Flow string `json:"flow"`
					} `json:"users"`
				} `json:"settings"`
				StreamSettings struct {
					Network  string `json:"network"`
					Security string `json:"security"`
					WS       struct {
						Path string `json:"path"`
						Host string `json:"host"`
					} `json:"wsSettings"`
					HTTPUpgrade struct {
						Path string `json:"path"`
						Host string `json:"host"`
					} `json:"httpupgradeSettings"`
					XHTTP struct {
						Path string `json:"path"`
						Host string `json:"host"`
						Mode string `json:"mode"`
					} `json:"xhttpSettings"`
					GRPC struct {
						ServiceName string `json:"serviceName"`
						Authority   string `json:"authority"`
						MultiMode   bool   `json:"multiMode"`
					} `json:"grpcSettings"`
					Reality struct {
						PrivateKey string `json:"privateKey"`
					} `json:"realitySettings"`
					TLS struct {
						Certificates []struct {
							Certificate []string `json:"certificate"`
						} `json:"certificates"`
					} `json:"tlsSettings"`
				} `json:"streamSettings"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(data, &config) == nil {
			plan := make(xrayconfig.Plan, 0, len(config.Inbounds))
			ports := make(map[string]int, len(config.Inbounds))
			var panelTLS *xrayconfig.TrojanTrust
			for _, in := range config.Inbounds {
				ports[in.Tag] = in.Port
				entry := xrayconfig.Inbound{Port: in.Port, Protocol: in.Protocol}
				if in.Protocol == "" {
					return view
				}
				if in.Protocol == "socks" {
					entry.Protocol = ""
				}
				if keyErr == nil && in.Protocol == xrayconfig.VLESS && (in.StreamSettings.Security == "" || in.StreamSettings.Security == "tls") {
					stream := &xrayconfig.VLESSStream{Network: in.StreamSettings.Network, Security: in.StreamSettings.Security}
					switch stream.Network {
					case "raw", "tcp":
						if stream.Security == "tls" {
							stream.Network = "tcp"
						} else {
							stream = nil
						}
					case "ws":
						stream.Path, stream.Host = in.StreamSettings.WS.Path, in.StreamSettings.WS.Host
					case "httpupgrade":
						stream.Path, stream.Host = in.StreamSettings.HTTPUpgrade.Path, in.StreamSettings.HTTPUpgrade.Host
					case "xhttp":
						stream.Path, stream.Host, stream.Mode = in.StreamSettings.XHTTP.Path, in.StreamSettings.XHTTP.Host, in.StreamSettings.XHTTP.Mode
					case "grpc":
						stream.ServiceName, stream.Authority, stream.MultiMode = in.StreamSettings.GRPC.ServiceName, in.StreamSettings.GRPC.Authority, in.StreamSettings.GRPC.MultiMode
					default:
						stream = nil
					}
					entry.VLESSStream = stream
				}
				if in.Protocol == xrayconfig.VLESS && in.StreamSettings.Security == "reality" {
					key, err := xrayconfig.RealityPublicKey(in.StreamSettings.Reality.PrivateKey)
					if err != nil {
						return view
					}
					entry.Protocol, entry.RealityPublicKey = xrayconfig.VLESSReality, key
				}
				if entry.UsesTLS() {
					certs := in.StreamSettings.TLS.Certificates
					if in.StreamSettings.Security != "tls" || len(certs) != 1 {
						return view
					}
					certificate := strings.Join(certs[0].Certificate, "\n")
					digest, err := xrayconfig.TrojanCertificateDigest(certificate)
					if err != nil {
						return view
					}
					entry.TLSCertSHA256 = digest
					if view.PanelTrojan {
						panelTLS = &xrayconfig.TrojanTrust{Certificate: certificate, SHA256: digest}
					}
				}
				if in.Listen == xrayconfig.PublicListenAddress {
					endpoint, ok := xrayconfig.PublishedEndpoint(in.Tag)
					if !ok {
						return view
					}
					entry.PublicEndpoint = endpoint
				}
				for _, user := range in.Settings.Users {
					name := user.User
					if xrayconfig.UsesProtocolCredentials(entry.Protocol) {
						name = user.Name
					}
					entry.Users = append(entry.Users, name)
					if user.Flow != "" {
						if entry.VLESSFlows == nil {
							entry.VLESSFlows = make(map[string]string)
						}
						entry.VLESSFlows[name] = user.Flow
					}
				}
				plan = append(plan, entry)
			}
			network, err := xrayconfig.AppliedNetwork(data, ports)
			if err == nil && (xrayconfig.Configuration{Inbounds: plan, Network: network}).Valid() {
				view.Applied = &plan
				view.AppliedNetwork = network
				view.PanelTLS = panelTLS
				view.StatisticsActive = view.PanelKey != "" && len(config.Stats) != 0
				if view.StatisticsActive && view.PanelStatistics && current.Running {
					view.Traffic = collectXrayTraffic(statsGroup, current.Revision, ports, plan, network)
				}
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
	plan, planErr := xrayconfig.ParseConfiguration(encoded)
	if err != nil || planErr != nil {
		return nil, xrayconfig.Reference{}, errors.New("node-local Xray catalog or plan is unavailable")
	}
	return catalog.RenderConfiguration(release.SHA256, plan)
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
	data, candidate, panel, err := r.renderCandidate(path, release, encoded)
	if err != nil || candidate != ref {
		return errors.New("local Xray configuration differs from the approved reference")
	}
	if err := r.verifyBundle(release); err != nil {
		return err
	}
	if err := r.checkConfigUnits(ctx, data, panel); err != nil {
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
	_, candidate, _, err = r.renderCandidate(path, release, encoded)
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

func configurationNetwork(data []byte) ([]string, []publishedInbound, bool, error) {
	var config struct {
		DNS struct {
			Tag           string   `json:"tag"`
			Servers       []string `json:"servers"`
			QueryStrategy string   `json:"queryStrategy"`
		} `json:"dns"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				DomainStrategy string `json:"domainStrategy"`
				FinalRules     []struct {
					Action string   `json:"action"`
					IP     []string `json:"ip"`
				} `json:"finalRules"`
			} `json:"settings"`
		} `json:"outbounds"`
		Inbounds []struct {
			Listen   string `json:"listen"`
			Tag      string `json:"tag"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Stream   struct {
				Security string `json:"security"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
		Routing struct {
			Rules []struct {
				IP       []string `json:"ip"`
				Network  string   `json:"network"`
				Tags     []string `json:"inboundTag"`
				Outbound string   `json:"outboundTag"`
				Port     int      `json:"port"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(data, &config) != nil {
		return nil, nil, false, errors.New("invalid saved Xray configuration")
	}
	if config.Inbounds == nil || (len(config.Inbounds) == 0 && len(config.Routing.Rules) != 0) {
		return nil, nil, false, errors.New("invalid saved Xray route")
	}
	direct, dnsOutbound := false, false
	for _, outbound := range config.Outbounds {
		if outbound.Tag == xrayconfig.PanelDNSTag {
			if dnsOutbound || outbound.Protocol != "freedom" || outbound.Settings.DomainStrategy != "" || len(outbound.Settings.FinalRules) != 0 {
				return nil, nil, false, errors.New("invalid Xray DNS outbound")
			}
			dnsOutbound = true
		}
		if outbound.Tag == "direct" {
			if direct || outbound.Protocol != "freedom" || outbound.Settings.DomainStrategy != "UseIPv4" ||
				config.DNS.Tag != xrayconfig.PanelDNSTag || !slices.Equal(config.DNS.Servers, []string{xrayconfig.PanelDNSAddress}) || config.DNS.QueryStrategy != "UseIPv4" ||
				len(outbound.Settings.FinalRules) != 1 ||
				outbound.Settings.FinalRules[0].Action != "block" ||
				!slices.Equal(outbound.Settings.FinalRules[0].IP, xrayconfig.PanelDirectBlockedIPs()) {
				return nil, nil, false, errors.New("invalid saved Xray direct outbound")
			}
			direct = true
		}
	}
	inboundProtocols := make(map[string]string, len(config.Inbounds))
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "" || inboundProtocols[inbound.Tag] != "" {
			return nil, nil, false, errors.New("invalid saved Xray inbound tag")
		}
		inboundProtocols[inbound.Tag] = inbound.Protocol
	}
	var destinations []string
	var socksTags []string
	for tag, protocol := range inboundProtocols {
		if protocol == "socks" {
			socksTags = append(socksTags, tag)
		}
	}
	slices.Sort(socksTags)
	directRules, dnsRules := 0, 0
	for _, rule := range config.Routing.Rules {
		if rule.Outbound == xrayconfig.PanelDNSTag {
			if !dnsOutbound || dnsRules != 0 || !slices.Equal(rule.Tags, []string{xrayconfig.PanelDNSTag}) ||
				rule.Network != "udp" || !slices.Equal(rule.IP, []string{xrayconfig.PanelDNSAddress + "/32"}) || rule.Port != 53 {
				return nil, nil, false, errors.New("invalid Xray DNS route")
			}
			dnsRules++
			continue
		}
		if rule.Outbound == "direct" {
			if !direct || directRules != 0 || len(rule.Tags) == 0 || rule.Network != "" || len(rule.IP) != 0 || rule.Port != 0 {
				return nil, nil, false, errors.New("invalid saved Xray direct route")
			}
			tags := slices.Clone(rule.Tags)
			slices.Sort(tags)
			if len(tags) != len(socksTags) || !slices.Equal(tags, socksTags) {
				return nil, nil, false, errors.New("Xray direct route must cover every SOCKS inbound")
			}
			for _, tag := range rule.Tags {
				if inboundProtocols[tag] != "socks" {
					return nil, nil, false, errors.New("Xray direct outbound is reserved for SOCKS inbounds")
				}
			}
			directRules++
			continue
		}
		if len(rule.IP) != 1 || rule.Network != "tcp" {
			return nil, nil, false, errors.New("invalid saved Xray route")
		}
		prefix, err := netip.ParsePrefix(rule.IP[0])
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
			return nil, nil, false, errors.New("invalid saved Xray route destination")
		}
		if !slices.Contains(destinations, rule.IP[0]) {
			destinations = append(destinations, rule.IP[0])
		}
	}
	if direct != (directRules == 1) || direct != dnsOutbound || direct != (dnsRules == 1) {
		return nil, nil, false, errors.New("Xray direct outbound and route do not match")
	}
	var published []publishedInbound
	for _, inbound := range config.Inbounds {
		endpoint, ok := xrayconfig.PublishedEndpoint(inbound.Tag)
		if inbound.Listen == "127.0.0.1" && !ok {
			continue
		}
		supported := (inbound.Protocol == "socks" && inbound.Stream.Security == "") ||
			(inbound.Protocol == xrayconfig.Trojan && inbound.Stream.Security == "tls") ||
			(inbound.Protocol == xrayconfig.VLESS && (inbound.Stream.Security == "reality" || inbound.Stream.Security == "tls" || inbound.Stream.Security == ""))
		if inbound.Listen != xrayconfig.PublicListenAddress || !ok || !supported || inbound.Port < 1024 || inbound.Port > 65535 {
			return nil, nil, false, errors.New("invalid saved Xray public listener")
		}
		published = append(published, publishedInbound{port: inbound.Port, endpoint: endpoint})
	}
	return destinations, published, direct, nil
}

func (r *Runtime) checkConfigUnits(ctx context.Context, data []byte, panel bool) error {
	destinations, published, _, err := configurationNetwork(data)
	if err != nil {
		return err
	}
	if panel {
		service, ok := r.service.(panelNetworkService)
		if !ok {
			return errors.New("Xray service cannot apply panel network policy")
		}
		if err := validatePanelAddresses(service, published); err != nil {
			return err
		}
		// Check the sandbox without altering the running revision's policy.
		return r.checkServiceUnits(ctx, nil, nil, false, networkPolicyBase)
	}
	return r.checkServiceUnits(ctx, destinations, published, true, networkPolicyBase)
}

func (r *Runtime) checkServiceUnits(ctx context.Context, destinations []string, published []publishedInbound, sockets bool, policy networkPolicy) error {
	service, ok := r.service.(interface {
		checkConfigUnits(context.Context, []string, []publishedInbound, bool, networkPolicy) error
	})
	if !ok {
		return errors.New("Xray service does not support isolated configuration")
	}
	return service.checkConfigUnits(ctx, destinations, published, sockets, policy)
}

func (r *Runtime) prepareRuntimeConfig(ctx context.Context, next selection) ([]publishedInbound, error) {
	if next.Release == (Release{}) {
		return nil, r.removeControl("runtime-config.json")
	}
	data := []byte(bootstrapConfig)
	var destinations []string
	var published []publishedInbound
	direct := false
	if next.Revision != 0 {
		var err error
		data, err = r.savedConfig(next.Config)
		if err != nil {
			return nil, err
		}
		if next.Running {
			destinations, published, direct, err = configurationNetwork(data)
			if err != nil {
				return nil, err
			}
		}
	}
	panel := false
	policy := networkPolicyRestricted
	if next.Running {
		_, err := r.panelKey()
		if err == nil {
			panel = true
			policy = networkPolicyPanel
			controller, ok := r.service.(panelNetworkService)
			if !ok {
				return nil, errors.New("Xray service cannot apply panel network policy")
			}
			if err := validatePanelAddresses(controller, published); err != nil {
				return nil, err
			}
			if err := controller.setPanelDestinations(ctx, destinations, len(published) > 0, direct); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if next.Revision != 0 {
			if direct {
				policy = networkPolicyPanel
			}
			if err := r.checkServiceUnits(ctx, destinations, published, false, policy); err != nil {
				return nil, err
			}
		}
	}
	if err := r.writeControl("runtime-config.json", data); err != nil {
		return nil, err
	}
	if panel {
		return published, nil
	}
	return nil, nil
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
