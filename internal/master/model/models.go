package model

import "github.com/ACnoway/mcui/pkg/proto"

type User struct {
	ID           uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	Username     string `json:"username" gorm:"uniqueIndex;size:64;not null"`
	PasswordHash string `json:"-" gorm:"not null"`
	SessionEpoch int64  `json:"-" gorm:"default:1"`
	CreatedAt    int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt    int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

type Node struct {
	ID              uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	Name            string `json:"name" gorm:"uniqueIndex;size:128;not null"`
	PublicHost      string `json:"publicHost" gorm:"size:255"`
	Remark          string `json:"remark" gorm:"size:255"`
	Enabled         bool   `json:"enabled" gorm:"default:true"`
	EnrollTokenHash string `json:"-" gorm:"index;size:64"`
	EnrollExpiresAt int64  `json:"enrollExpiresAt"`
	NodeTokenHash   string `json:"-" gorm:"uniqueIndex;size:64"`
	ConfigDirty     bool   `json:"configDirty" gorm:"default:false"`

	Online       bool    `json:"online" gorm:"-"`
	LastSeenAt   int64   `json:"lastSeenAt"`
	AgentVersion string  `json:"agentVersion" gorm:"size:32"`
	Hostname     string  `json:"hostname" gorm:"size:128"`
	OS           string  `json:"os" gorm:"size:32"`
	Arch         string  `json:"arch" gorm:"size:32"`
	PublicIPv4   string  `json:"publicIpv4" gorm:"size:64"`
	PublicIPv6   string  `json:"publicIpv6" gorm:"size:128"`
	CPUPercent   float64 `json:"cpuPercent"`
	CPUCores     int     `json:"cpuCores"`
	MemUsed      uint64  `json:"memUsed"`
	MemTotal     uint64  `json:"memTotal"`
	DiskUsed     uint64  `json:"diskUsed"`
	DiskTotal    uint64  `json:"diskTotal"`
	NetUpRate    uint64  `json:"netUpRate"`
	NetDownRate  uint64  `json:"netDownRate"`
	NetUpTotal   uint64  `json:"netUpTotal"`
	NetDownTotal uint64  `json:"netDownTotal"`
	Uptime       uint64  `json:"uptime"`

	Cores     []NodeCore `json:"cores" gorm:"foreignKey:NodeID;constraint:OnDelete:CASCADE"`
	CreatedAt int64      `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt int64      `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

type NodeCore struct {
	ID               uint            `json:"id" gorm:"primaryKey;autoIncrement"`
	NodeID           uint            `json:"nodeId" gorm:"uniqueIndex:idx_node_core,priority:1;not null"`
	CoreType         proto.CoreType  `json:"coreType" gorm:"uniqueIndex:idx_node_core,priority:2;size:32;not null"`
	Installed        bool            `json:"installed" gorm:"default:false"`
	InstalledVersion string          `json:"installedVersion" gorm:"size:64"`
	DesiredVersion   string          `json:"desiredVersion" gorm:"size:64"`
	State            proto.CoreState `json:"state" gorm:"size:32;default:'uninstalled'"`
	ErrorMsg         string          `json:"errorMsg"`
	ProgressPct      int             `json:"progressPct"`
	ConfigHash       string          `json:"configHash" gorm:"size:64"`
	UpdatedAt        int64           `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

type Inbound struct {
	ID             uint               `json:"id" gorm:"primaryKey;autoIncrement"`
	NodeID         uint               `json:"nodeId" gorm:"index;not null;uniqueIndex:idx_node_port,priority:1"`
	CoreType       proto.CoreType     `json:"coreType" gorm:"size:32;not null;default:'xray'"`
	Tag            string             `json:"tag" gorm:"uniqueIndex;size:128;not null"`
	Remark         string             `json:"remark" gorm:"size:128;not null"`
	Enable         bool               `json:"enable" gorm:"default:true"`
	Listen         string             `json:"listen" gorm:"size:64;default:'0.0.0.0'"`
	Port           int                `json:"port" gorm:"not null;uniqueIndex:idx_node_port,priority:2"`
	Protocol       proto.ProtocolType `json:"protocol" gorm:"size:32;not null"`
	Settings       string             `json:"settings" gorm:"type:text"`
	StreamSettings string             `json:"streamSettings" gorm:"type:text"`
	Sniffing       string             `json:"sniffing" gorm:"type:text"`
	Up             int64              `json:"up" gorm:"default:0"`
	Down           int64              `json:"down" gorm:"default:0"`

	NodeName    string `json:"nodeName,omitempty" gorm:"-"`
	ClientCount int    `json:"clientCount" gorm:"-"`
	CreatedAt   int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt   int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

// Client is defined centrally on Master and attached to Inbounds across any Node.
type Client struct {
	ID         uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	Email      string `json:"email" gorm:"uniqueIndex;size:128;not null"`
	SubID      string `json:"subId" gorm:"uniqueIndex;size:64;not null"`
	UUID       string `json:"uuid" gorm:"size:64;not null"`
	Password   string `json:"password" gorm:"size:128;not null"`
	Flow       string `json:"flow" gorm:"size:64"`
	TotalBytes int64  `json:"totalBytes" gorm:"default:0"` // 0 = unlimited
	Up         int64  `json:"up" gorm:"default:0"`
	Down       int64  `json:"down" gorm:"default:0"`
	ExpiryTime int64  `json:"expiryTime" gorm:"default:0"` // unix ms; 0 = never
	Enable     bool   `json:"enable" gorm:"default:true"`
	Comment    string `json:"comment" gorm:"size:255"`

	InboundIDs []uint `json:"inboundIds" gorm:"-"`
	CreatedAt  int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt  int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

type ClientInbound struct {
	ClientID     uint   `json:"clientId" gorm:"primaryKey"`
	InboundID    uint   `json:"inboundId" gorm:"primaryKey;index"`
	FlowOverride string `json:"flowOverride" gorm:"size:64"`
	CreatedAt    int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
}

type Setting struct {
	Key   string `json:"key" gorm:"primaryKey;size:64"`
	Value string `json:"value" gorm:"type:text"`
}
