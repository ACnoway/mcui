package lifecycleauth

import (
	"slices"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

// NodeInventory travels in authenticated heartbeats. A missing Xray value
// means the local Helper could not report a committed installation state.
type NodeInventory struct {
	Architecture string         `json:"architecture"`
	Xray         *XrayInventory `json:"xray,omitempty"`
}

type XrayInventory struct {
	Version          string                  `json:"version"`
	SHA256           string                  `json:"sha256"`
	Running          bool                    `json:"running"`
	Candidate        xrayconfig.Reference    `json:"candidate,omitzero"`
	Config           xrayconfig.Reference    `json:"config,omitzero"`
	ConfigRevision   int64                   `json:"config_revision,omitempty"`
	Catalog          *xrayconfig.Catalog     `json:"catalog,omitempty"`
	Preview          string                  `json:"preview,omitempty"`
	Applied          *xrayconfig.Plan        `json:"applied,omitempty"`
	AppliedNetwork   *xrayconfig.Network     `json:"applied_network,omitempty"`
	PlanSupported    bool                    `json:"plan_supported,omitempty"`
	PanelKey         string                  `json:"panel_key,omitempty"`
	PanelMultiClient bool                    `json:"panel_multi_client,omitempty"`
	PanelTrojan      bool                    `json:"panel_trojan,omitempty"`
	PanelAddresses   []string                `json:"panel_addresses,omitempty"`
	PanelTLS         *xrayconfig.TrojanTrust `json:"panel_tls,omitempty"`
}

func (i NodeInventory) Valid() bool {
	if i.Architecture != "amd64" && i.Architecture != "arm64" {
		return false
	}
	if i.Xray == nil {
		return true
	}
	return i.Xray.Valid() && (i.Architecture == xrayconfig.Architecture ||
		(i.Xray.Candidate == (xrayconfig.Reference{}) && i.Xray.Config == (xrayconfig.Reference{}) && i.Xray.Catalog == nil && i.Xray.PanelKey == ""))
}

func (x XrayInventory) Valid() bool {
	if x.PanelKey != "" && (!x.PlanSupported || x.Catalog != nil || !security.ValidNodeSecret(x.PanelKey) ||
		(x.Candidate.Valid() && !xrayconfig.ValidPlanDigest(x.Preview))) {
		return false
	}
	if (x.PanelTrojan || x.PanelMultiClient) && x.PanelKey == "" || !x.PanelTrojan && (len(x.PanelAddresses) != 0 || x.PanelTLS != nil) ||
		len(x.PanelAddresses) > 16 || !slices.IsSorted(x.PanelAddresses) {
		return false
	}
	for i, address := range x.PanelAddresses {
		if !(xrayconfig.PublicEndpoint{Address: address, Port: 1}).Valid() || (i > 0 && x.PanelAddresses[i-1] == address) {
			return false
		}
	}
	if x.PanelTLS != nil && (!x.PanelTLS.Valid() || x.Applied == nil) {
		return false
	}
	if x.PanelKey != "" && x.Applied != nil {
		usesTLS := false
		for _, in := range *x.Applied {
			if in.Protocol == xrayconfig.Trojan {
				usesTLS = true
				if x.PanelTLS == nil || in.TLSCertSHA256 != x.PanelTLS.SHA256 {
					return false
				}
			}
		}
		if usesTLS != (x.PanelTLS != nil) {
			return false
		}
	}
	if !x.PlanSupported && (x.Catalog != nil || x.Preview != "" || x.Applied != nil) {
		return false
	}
	if x.Catalog != nil {
		if x.Version != xrayconfig.Version || !x.Catalog.Valid() ||
			(x.Candidate.Valid() && !xrayconfig.ValidPlanDigest(x.Preview)) {
			return false
		}
	}
	if x.Preview != "" && ((x.Catalog == nil && x.PanelKey == "") || !xrayconfig.ValidPlanDigest(x.Preview)) {
		return false
	}
	if x.AppliedNetwork != nil && x.Applied == nil {
		return false
	}
	if x.Applied != nil && (x.ConfigRevision == 0 || !x.AppliedConfiguration().Valid()) {
		return false
	}
	if x.Candidate != (xrayconfig.Reference{}) && (x.Version != xrayconfig.Version || !x.Candidate.Valid()) {
		return false
	}
	if x.Config != (xrayconfig.Reference{}) || x.ConfigRevision != 0 {
		if x.Version != xrayconfig.Version || !x.Config.Valid() || x.ConfigRevision <= 0 || x.ConfigRevision > maxSequence {
			return false
		}
	}
	return (x.Version == "" && x.SHA256 == "" && !x.Running) || corecatalog.ValidXrayRelease(x.Version, x.SHA256)
}

func (x XrayInventory) AppliedConfiguration() xrayconfig.Configuration {
	if x.Applied == nil {
		return xrayconfig.Configuration{}
	}
	return xrayconfig.Configuration{Inbounds: *x.Applied, Network: x.AppliedNetwork}
}
