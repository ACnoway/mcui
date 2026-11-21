package lifecycleauth

import (
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

// NodeInventory travels in authenticated heartbeats. A missing Xray value
// means the local Helper could not report a committed installation state.
type NodeInventory struct {
	Architecture string         `json:"architecture"`
	Xray         *XrayInventory `json:"xray,omitempty"`
}

type XrayInventory struct {
	Version        string               `json:"version"`
	SHA256         string               `json:"sha256"`
	Running        bool                 `json:"running"`
	Candidate      xrayconfig.Reference `json:"candidate,omitzero"`
	Config         xrayconfig.Reference `json:"config,omitzero"`
	ConfigRevision int64                `json:"config_revision,omitempty"`
}

func (i NodeInventory) Valid() bool {
	if i.Architecture != "amd64" && i.Architecture != "arm64" {
		return false
	}
	if i.Xray == nil {
		return true
	}
	return i.Xray.Valid() && (i.Architecture == xrayconfig.Architecture ||
		(i.Xray.Candidate == (xrayconfig.Reference{}) && i.Xray.Config == (xrayconfig.Reference{})))
}

func (x XrayInventory) Valid() bool {
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
