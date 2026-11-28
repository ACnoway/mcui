package proto

import "encoding/json"

type CoreType string

const (
	CoreXray CoreType = "xray"
)

type CoreState string

const (
	CoreUninstalled CoreState = "uninstalled"
	CoreInstalling  CoreState = "installing"
	CoreStopped     CoreState = "stopped"
	CoreRunning     CoreState = "running"
	CoreError       CoreState = "error"
)

type ProtocolType string

const (
	ProtocolVLESS       ProtocolType = "vless"
	ProtocolVMess       ProtocolType = "vmess"
	ProtocolTrojan      ProtocolType = "trojan"
	ProtocolShadowsocks ProtocolType = "shadowsocks"
)

type SystemMetrics struct {
	Hostname    string  `json:"hostname"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	PublicIPv4  string  `json:"publicIpv4,omitempty"`
	PublicIPv6  string  `json:"publicIpv6,omitempty"`
	CPUPercent  float64 `json:"cpuPercent"`
	CPUCores    int     `json:"cpuCores"`
	MemUsed     uint64  `json:"memUsed"`
	MemTotal    uint64  `json:"memTotal"`
	DiskUsed    uint64  `json:"diskUsed"`
	DiskTotal   uint64  `json:"diskTotal"`
	NetUpRate   uint64  `json:"netUpRate"`
	NetDownRate uint64  `json:"netDownRate"`
	NetUpTotal  uint64  `json:"netUpTotal"`
	NetDownTotal uint64 `json:"netDownTotal"`
	Uptime      uint64  `json:"uptime"`
}

type CoreStatus struct {
	CoreType    CoreType  `json:"coreType"`
	Installed   bool      `json:"installed"`
	Version     string    `json:"version,omitempty"`
	State       CoreState `json:"state"`
	ErrorMsg    string    `json:"errorMsg,omitempty"`
	ProgressPct int       `json:"progressPct,omitempty"`
	ConfigHash  string    `json:"configHash,omitempty"`
}

type TrafficCounter struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// AgentReport is sent periodically by Agent over the reverse tunnel to Master.
type AgentReport struct {
	AgentVersion   string                    `json:"agentVersion"`
	System         SystemMetrics             `json:"system"`
	Cores          []CoreStatus              `json:"cores"`
	UserTraffic    map[string]TrafficCounter `json:"userTraffic,omitempty"`
	InboundTraffic map[string]TrafficCounter `json:"inboundTraffic,omitempty"`
	Timestamp      int64                     `json:"timestamp"`
}

// InstallCoreRequest instructs the Agent to download, verify, and install a proxy core.
type InstallCoreRequest struct {
	CoreType   CoreType `json:"coreType"`
	Version    string   `json:"version"`
	ArchiveURL string   `json:"archiveUrl"`
	SHA256     string   `json:"sha256,omitempty"`
}

type UninstallCoreRequest struct {
	CoreType CoreType `json:"coreType"`
}

type CoreActionRequest struct {
	CoreType CoreType `json:"coreType"`
	Action   string   `json:"action"` // "start" | "stop" | "restart"
}

type InboundUserSpec struct {
	Email    string `json:"email"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Security string `json:"security,omitempty"`
}

type InboundSpec struct {
	Tag            string           `json:"tag"`
	Protocol       ProtocolType     `json:"protocol"`
	Listen         string           `json:"listen"`
	Port           int              `json:"port"`
	Settings       json.RawMessage  `json:"settings,omitempty"`
	StreamSettings json.RawMessage  `json:"streamSettings,omitempty"`
	Sniffing       json.RawMessage  `json:"sniffing,omitempty"`
	Users          []InboundUserSpec `json:"users"`
}

// DesiredCoreSpec represents the declarative state of a single Core on an Agent node.
type DesiredCoreSpec struct {
	CoreType CoreType      `json:"coreType"`
	Inbounds []InboundSpec `json:"inbounds"`
}

type ApplyStateResponse struct {
	Applied    bool   `json:"applied"`
	HotApplied bool   `json:"hotApplied"`
	ConfigHash string `json:"configHash"`
}

type EnrollRequest struct {
	EnrollToken string `json:"enrollToken"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
}

type EnrollResponse struct {
	NodeID    uint   `json:"nodeId"`
	NodeName  string `json:"nodeName"`
	NodeToken string `json:"nodeToken"`
}

type APIEnvelope[T any] struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg,omitempty"`
	Obj     T      `json:"obj,omitempty"`
}
