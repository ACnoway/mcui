package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const xrayReleasesAPI = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=25"

type CoreService struct {
	db         *gorm.DB
	tunnels    *tunnel.Manager
	httpClient *http.Client
	releasesURL string

	mu            sync.Mutex
	cachedVersions []string
	cachedAt      time.Time
}

func NewCoreService(gdb *gorm.DB, tunnels *tunnel.Manager) *CoreService {
	return &CoreService{
		db:          gdb,
		tunnels:     tunnels,
		httpClient:  &http.Client{Timeout: 20 * time.Second},
		releasesURL: xrayReleasesAPI,
	}
}

func (s *CoreService) SetReleasesURLForTest(url string) {
	s.releasesURL = url
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
}

func (s *CoreService) ListAvailableVersions(ctx context.Context, coreType proto.CoreType, forceRefresh bool) ([]string, error) {
	if coreType != proto.CoreXray {
		return nil, fmt.Errorf("unsupported core type %q", coreType)
	}

	s.mu.Lock()
	if !forceRefresh && len(s.cachedVersions) > 0 && time.Since(s.cachedAt) < 15*time.Minute {
		out := make([]string, len(s.cachedVersions))
		copy(out, s.cachedVersions)
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.releasesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mcui-master")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch xray releases: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github releases HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var releases []githubRelease
	if err := json.Unmarshal(raw, &releases); err != nil {
		return nil, err
	}

	versions := make([]string, 0, len(releases))
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease || rel.TagName == "" {
			continue
		}
		versions = append(versions, rel.TagName)
	}
	if len(versions) == 0 {
		return nil, errors.New("no stable xray releases found")
	}

	s.mu.Lock()
	s.cachedVersions = versions
	s.cachedAt = time.Now()
	s.mu.Unlock()

	return versions, nil
}

// XrayAssetName maps Go's GOOS/GOARCH reported by the Agent to Xray's release zip filename.
func XrayAssetName(goos, goarch string) (string, error) {
	var osPart string
	switch goos {
	case "linux":
		osPart = "linux"
	case "darwin":
		osPart = "macos"
	case "windows":
		osPart = "windows"
	default:
		return "", fmt.Errorf("unsupported node OS %q", goos)
	}

	var archPart string
	switch goarch {
	case "amd64":
		archPart = "64"
	case "arm64":
		archPart = "arm64-v8a"
	case "386":
		archPart = "32"
	case "s390x":
		archPart = "s390x"
	default:
		return "", fmt.Errorf("unsupported node arch %q", goarch)
	}

	return fmt.Sprintf("Xray-%s-%s.zip", osPart, archPart), nil
}

func (s *CoreService) fetchXrayDGST(ctx context.Context, dgstURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dgstURL, nil)
	if err != nil {
		return ""
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "SHA2-256=") {
			return strings.TrimSpace(line[len("SHA2-256="):])
		}
	}
	return ""
}

type InstallNodeCoreInput struct {
	CoreType   proto.CoreType `json:"coreType"`
	Version    string         `json:"version"`
	ArchiveURL string         `json:"archiveUrl,omitempty"`
	SHA256     string         `json:"sha256,omitempty"`
}

func (s *CoreService) InstallOnNode(ctx context.Context, nodeID uint, in InstallNodeCoreInput) (proto.CoreStatus, error) {
	if in.CoreType == "" {
		in.CoreType = proto.CoreXray
	}
	if in.CoreType != proto.CoreXray {
		return proto.CoreStatus{}, fmt.Errorf("unsupported core type %q", in.CoreType)
	}

	var node model.Node
	if err := s.db.First(&node, nodeID).Error; err != nil {
		return proto.CoreStatus{}, err
	}
	if !s.tunnels.IsOnline(nodeID) {
		return proto.CoreStatus{}, tunnel.ErrNodeOffline
	}

	version := strings.TrimSpace(in.Version)
	if version == "" || version == "latest" {
		vers, err := s.ListAvailableVersions(ctx, in.CoreType, false)
		if err != nil {
			return proto.CoreStatus{}, err
		}
		version = vers[0]
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	archiveURL := strings.TrimSpace(in.ArchiveURL)
	sha256Hex := strings.TrimSpace(in.SHA256)
	if archiveURL == "" {
		asset, err := XrayAssetName(node.OS, node.Arch)
		if err != nil {
			return proto.CoreStatus{}, err
		}
		archiveURL = fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, asset)
		if sha256Hex == "" {
			sha256Hex = s.fetchXrayDGST(ctx, archiveURL+".dgst")
		}
	}

	st, err := s.tunnels.InstallCore(ctx, nodeID, proto.InstallCoreRequest{
		CoreType:   in.CoreType,
		Version:    version,
		ArchiveURL: archiveURL,
		SHA256:     sha256Hex,
	})
	if err != nil {
		return proto.CoreStatus{}, err
	}

	nc := model.NodeCore{
		NodeID:         nodeID,
		CoreType:       in.CoreType,
		DesiredVersion: version,
		State:          proto.CoreInstalling,
	}
	_ = s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "node_id"}, {Name: "core_type"}},
		DoUpdates: clause.AssignmentColumns([]string{"desired_version", "state", "updated_at"}),
	}).Create(&nc).Error

	// Mark node dirty so once installation finishes, any already-configured inbounds get reconciled onto it.
	_ = s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", true).Error

	return st, nil
}

func (s *CoreService) UninstallOnNode(ctx context.Context, nodeID uint, coreType proto.CoreType) (proto.CoreStatus, error) {
	var inboundCount int64
	if err := s.db.Model(&model.Inbound{}).Where("node_id = ? AND core_type = ?", nodeID, coreType).Count(&inboundCount).Error; err != nil {
		return proto.CoreStatus{}, err
	}
	if inboundCount > 0 {
		return proto.CoreStatus{}, fmt.Errorf("cannot uninstall %s while %d inbound(s) still exist on this node", coreType, inboundCount)
	}
	return s.tunnels.UninstallCore(ctx, nodeID, coreType)
}

func (s *CoreService) ControlOnNode(ctx context.Context, nodeID uint, coreType proto.CoreType, action string) (proto.CoreStatus, error) {
	return s.tunnels.CoreAction(ctx, nodeID, coreType, action)
}

func (s *CoreService) GetLogs(ctx context.Context, nodeID uint, coreType proto.CoreType, lines int) ([]string, error) {
	if lines <= 0 {
		lines = 200
	}
	return s.tunnels.CoreLogs(ctx, nodeID, coreType, lines)
}
