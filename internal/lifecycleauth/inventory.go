package lifecycleauth

import "github.com/ACnoway/mcui/internal/corecatalog"

// NodeInventory travels in authenticated heartbeats. A missing Xray value
// means the local Helper could not report a committed installation state.
type NodeInventory struct {
	Architecture string         `json:"architecture"`
	Xray         *XrayInventory `json:"xray,omitempty"`
}

type XrayInventory struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Running bool   `json:"running"`
}

func (i NodeInventory) Valid() bool {
	return (i.Architecture == "amd64" || i.Architecture == "arm64") && (i.Xray == nil || i.Xray.Valid())
}

func (x XrayInventory) Valid() bool {
	return (x.Version == "" && x.SHA256 == "" && !x.Running) || corecatalog.ValidXrayRelease(x.Version, x.SHA256)
}
