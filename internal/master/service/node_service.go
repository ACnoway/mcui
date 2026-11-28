package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/master/hub"
	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/crypto"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type NodeService struct {
	db      *gorm.DB
	tunnels *tunnel.Manager
	wsHub   *hub.Hub
}

func NewNodeService(gdb *gorm.DB, tunnels *tunnel.Manager, wsHub *hub.Hub) *NodeService {
	return &NodeService{
		db:      gdb,
		tunnels: tunnels,
		wsHub:   wsHub,
	}
}

type CreateNodeInput struct {
	Name       string `json:"name"`
	PublicHost string `json:"publicHost"`
	Remark     string `json:"remark"`
}

type UpdateNodeInput struct {
	Name       string `json:"name"`
	PublicHost string `json:"publicHost"`
	Remark     string `json:"remark"`
	Enabled    *bool  `json:"enabled,omitempty"`
}

type NodeWithEnroll struct {
	Node        model.Node `json:"node"`
	EnrollToken string     `json:"enrollToken"`
}

func (s *NodeService) CreateNode(in CreateNodeInput) (*NodeWithEnroll, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, errors.New("node name is required")
	}
	enrollToken, err := crypto.RandomHex(20)
	if err != nil {
		return nil, err
	}
	node := model.Node{
		Name:            name,
		PublicHost:      strings.TrimSpace(in.PublicHost),
		Remark:          strings.TrimSpace(in.Remark),
		Enabled:         true,
		EnrollTokenHash: crypto.SHA256Hex(enrollToken),
		EnrollExpiresAt: time.Now().Add(24 * time.Hour).UnixMilli(),
	}
	if err := s.db.Create(&node).Error; err != nil {
		return nil, fmt.Errorf("create node: %w", err)
	}
	return &NodeWithEnroll{Node: node, EnrollToken: enrollToken}, nil
}

func (s *NodeService) RotateEnrollToken(nodeID uint, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	enrollToken, err := crypto.RandomHex(20)
	if err != nil {
		return "", err
	}
	res := s.db.Model(&model.Node{}).Where("id = ?", nodeID).Updates(map[string]any{
		"enroll_token_hash": crypto.SHA256Hex(enrollToken),
		"enroll_expires_at": time.Now().Add(ttl).UnixMilli(),
	})
	if res.Error != nil {
		return "", res.Error
	}
	if res.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}
	return enrollToken, nil
}

func (s *NodeService) UpdateNode(nodeID uint, in UpdateNodeInput) (*model.Node, error) {
	var node model.Node
	if err := s.db.Preload("Cores").First(&node, nodeID).Error; err != nil {
		return nil, err
	}
	if name := strings.TrimSpace(in.Name); name != "" {
		node.Name = name
	}
	node.PublicHost = strings.TrimSpace(in.PublicHost)
	node.Remark = strings.TrimSpace(in.Remark)
	if in.Enabled != nil {
		node.Enabled = *in.Enabled
		if !node.Enabled && s.tunnels != nil {
			s.tunnels.Disconnect(nodeID)
		}
	}
	if err := s.db.Save(&node).Error; err != nil {
		return nil, err
	}
	if s.tunnels != nil {
		node.Online = s.tunnels.IsOnline(node.ID)
	}
	return &node, nil
}

func (s *NodeService) DeleteNode(nodeID uint) error {
	if s.tunnels != nil {
		s.tunnels.Disconnect(nodeID)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var inboundIDs []uint
		if err := tx.Model(&model.Inbound{}).Where("node_id = ?", nodeID).Pluck("id", &inboundIDs).Error; err != nil {
			return err
		}
		if len(inboundIDs) > 0 {
			if err := tx.Where("inbound_id IN ?", inboundIDs).Delete(&model.ClientInbound{}).Error; err != nil {
				return err
			}
			if err := tx.Where("id IN ?", inboundIDs).Delete(&model.Inbound{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("node_id = ?", nodeID).Delete(&model.NodeCore{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.Node{}, nodeID).Error
	})
}

func (s *NodeService) ListNodes() ([]model.Node, error) {
	var nodes []model.Node
	if err := s.db.Preload("Cores").Order("id ASC").Find(&nodes).Error; err != nil {
		return nil, err
	}
	for i := range nodes {
		if s.tunnels != nil {
			nodes[i].Online = s.tunnels.IsOnline(nodes[i].ID)
		}
	}
	return nodes, nil
}

func (s *NodeService) GetNode(nodeID uint) (*model.Node, error) {
	var node model.Node
	if err := s.db.Preload("Cores").First(&node, nodeID).Error; err != nil {
		return nil, err
	}
	if s.tunnels != nil {
		node.Online = s.tunnels.IsOnline(node.ID)
	}
	return &node, nil
}

func (s *NodeService) Enroll(req proto.EnrollRequest) (*proto.EnrollResponse, error) {
	rawToken := strings.TrimSpace(req.EnrollToken)
	if rawToken == "" {
		return nil, errors.New("enrollToken is required")
	}
	tokenHash := crypto.SHA256Hex(rawToken)

	var resp proto.EnrollResponse
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var node model.Node
		if err := tx.Where("enroll_token_hash = ?", tokenHash).First(&node).Error; err != nil {
			return errors.New("invalid or already-consumed enrollment token")
		}
		if time.Now().UnixMilli() > node.EnrollExpiresAt {
			return errors.New("enrollment token has expired")
		}

		nodeToken, err := crypto.RandomHex(32)
		if err != nil {
			return err
		}
		node.NodeTokenHash = crypto.SHA256Hex(nodeToken)
		node.EnrollTokenHash = ""
		node.EnrollExpiresAt = 0
		node.Hostname = req.Hostname
		node.OS = req.OS
		node.Arch = req.Arch
		node.Enabled = true
		node.ConfigDirty = true

		if err := tx.Save(&node).Error; err != nil {
			return err
		}

		resp = proto.EnrollResponse{
			NodeID:    node.ID,
			NodeName:  node.Name,
			NodeToken: nodeToken,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s *NodeService) AuthenticateNodeToken(rawBearer string) (*model.Node, error) {
	token := strings.TrimSpace(strings.TrimPrefix(rawBearer, "Bearer"))
	if token == "" {
		return nil, errors.New("missing bearer token")
	}
	hash := crypto.SHA256Hex(token)
	var node model.Node
	if err := s.db.Where("node_token_hash = ? AND enabled = ?", hash, true).First(&node).Error; err != nil {
		return nil, errors.New("invalid or disabled node token")
	}
	return &node, nil
}

func (s *NodeService) MarkDirty(nodeID uint) error {
	return s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", true).Error
}

func (s *NodeService) ClearDirty(nodeID uint) error {
	return s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", false).Error
}

// HandleAgentReport persists system metrics, core statuses, and traffic deltas reported by an Agent.
// Returns affectedClientEmails if any client exceeded quota or expired during this report tick.
func (s *NodeService) HandleAgentReport(nodeID uint, rep proto.AgentReport) ([]uint, error) {
	now := time.Now().UnixMilli()
	var depletedNodeIDs []uint

	err := s.db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]any{
			"last_seen_at":   now,
			"agent_version":  rep.AgentVersion,
			"hostname":       rep.System.Hostname,
			"os":             rep.System.OS,
			"arch":           rep.System.Arch,
			"cpu_percent":    rep.System.CPUPercent,
			"cpu_cores":      rep.System.CPUCores,
			"mem_used":       rep.System.MemUsed,
			"mem_total":      rep.System.MemTotal,
			"disk_used":      rep.System.DiskUsed,
			"disk_total":     rep.System.DiskTotal,
			"net_up_rate":    rep.System.NetUpRate,
			"net_down_rate":  rep.System.NetDownRate,
			"net_up_total":   rep.System.NetUpTotal,
			"net_down_total": rep.System.NetDownTotal,
			"uptime":         rep.System.Uptime,
		}
		if rep.System.PublicIPv4 != "" {
			updates["public_ipv4"] = rep.System.PublicIPv4
		}
		if rep.System.PublicIPv6 != "" {
			updates["public_ipv6"] = rep.System.PublicIPv6
		}
		if err := tx.Model(&model.Node{}).Where("id = ?", nodeID).Updates(updates).Error; err != nil {
			return err
		}

		for _, cs := range rep.Cores {
			row := model.NodeCore{
				NodeID:           nodeID,
				CoreType:         cs.CoreType,
				Installed:        cs.Installed,
				InstalledVersion: cs.Version,
				State:            cs.State,
				ErrorMsg:         cs.ErrorMsg,
				ProgressPct:      cs.ProgressPct,
				ConfigHash:       cs.ConfigHash,
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "node_id"}, {Name: "core_type"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"installed", "installed_version", "state", "error_msg", "progress_pct", "config_hash", "updated_at",
				}),
			}).Create(&row).Error; err != nil {
				return err
			}
		}

		for tag, delta := range rep.InboundTraffic {
			if delta.Up == 0 && delta.Down == 0 {
				continue
			}
			if err := tx.Model(&model.Inbound{}).
				Where("node_id = ? AND tag = ?", nodeID, tag).
				Updates(map[string]any{
					"up":   gorm.Expr("up + ?", delta.Up),
					"down": gorm.Expr("down + ?", delta.Down),
				}).Error; err != nil {
				return err
			}
		}

		var exhaustedClientIDs []uint
		for email, delta := range rep.UserTraffic {
			if delta.Up == 0 && delta.Down == 0 {
				continue
			}
			if err := tx.Model(&model.Client{}).
				Where("email = ?", email).
				Updates(map[string]any{
					"up":   gorm.Expr("up + ?", delta.Up),
					"down": gorm.Expr("down + ?", delta.Down),
				}).Error; err != nil {
				return err
			}

			var cl model.Client
			if err := tx.Where("email = ?", email).First(&cl).Error; err == nil && cl.Enable {
				overQuota := cl.TotalBytes > 0 && (cl.Up+cl.Down) >= cl.TotalBytes
				expired := cl.ExpiryTime > 0 && now >= cl.ExpiryTime
				if overQuota || expired {
					_ = tx.Model(&model.Client{}).Where("id = ?", cl.ID).Update("enable", false).Error
					exhaustedClientIDs = append(exhaustedClientIDs, cl.ID)
				}
			}
		}

		if len(exhaustedClientIDs) > 0 {
			if err := tx.Model(&model.Inbound{}).
				Distinct("inbounds.node_id").
				Joins("JOIN client_inbounds ON client_inbounds.inbound_id = inbounds.id").
				Where("client_inbounds.client_id IN ?", exhaustedClientIDs).
				Pluck("inbounds.node_id", &depletedNodeIDs).Error; err != nil {
				return err
			}
			if len(depletedNodeIDs) > 0 {
				_ = tx.Model(&model.Node{}).Where("id IN ?", depletedNodeIDs).Update("config_dirty", true).Error
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if s.wsHub != nil {
		if updated, gerr := s.GetNode(nodeID); gerr == nil {
			s.wsHub.Broadcast("node.updated", updated)
		}
	}
	return depletedNodeIDs, nil
}
