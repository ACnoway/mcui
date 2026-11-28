package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/pkg/crypto"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
)

type InboundService struct {
	db        *gorm.DB
	reconcile *ReconcileService
}

func NewInboundService(gdb *gorm.DB, reconcile *ReconcileService) *InboundService {
	return &InboundService{db: gdb, reconcile: reconcile}
}

type InboundInput struct {
	NodeID         uint               `json:"nodeId"`
	CoreType       proto.CoreType     `json:"coreType"`
	Remark         string             `json:"remark"`
	Enable         *bool              `json:"enable,omitempty"`
	Listen         string             `json:"listen"`
	Port           int                `json:"port"`
	Protocol       proto.ProtocolType `json:"protocol"`
	Settings       json.RawMessage    `json:"settings,omitempty"`
	StreamSettings json.RawMessage    `json:"streamSettings,omitempty"`
	Sniffing       json.RawMessage    `json:"sniffing,omitempty"`
}

func validateInboundInput(in InboundInput) error {
	if in.NodeID == 0 {
		return errors.New("nodeId is required")
	}
	if in.Port < 1 || in.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	switch in.Protocol {
	case proto.ProtocolVLESS, proto.ProtocolVMess, proto.ProtocolTrojan, proto.ProtocolShadowsocks:
	default:
		return fmt.Errorf("unsupported protocol %q", in.Protocol)
	}
	for _, raw := range []json.RawMessage{in.Settings, in.StreamSettings, in.Sniffing} {
		if len(raw) > 0 && !json.Valid(raw) {
			return errors.New("invalid JSON in inbound settings/streamSettings/sniffing")
		}
	}
	return nil
}

func (s *InboundService) ListInbounds(nodeID uint) ([]model.Inbound, error) {
	var list []model.Inbound
	q := s.db.Order("id ASC")
	if nodeID > 0 {
		q = q.Where("node_id = ?", nodeID)
	}
	if err := q.Find(&list).Error; err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return list, nil
	}

	var nodes []model.Node
	_ = s.db.Select("id, name").Find(&nodes).Error
	nodeNames := make(map[uint]string, len(nodes))
	for _, n := range nodes {
		nodeNames[n.ID] = n.Name
	}

	type countRow struct {
		InboundID uint
		Cnt       int
	}
	var counts []countRow
	_ = s.db.Table("client_inbounds").
		Select("inbound_id, COUNT(*) AS cnt").
		Group("inbound_id").
		Scan(&counts).Error
	countMap := make(map[uint]int, len(counts))
	for _, c := range counts {
		countMap[c.InboundID] = c.Cnt
	}

	for i := range list {
		list[i].NodeName = nodeNames[list[i].NodeID]
		list[i].ClientCount = countMap[list[i].ID]
	}
	return list, nil
}

func (s *InboundService) CreateInbound(ctx context.Context, in InboundInput) (*model.Inbound, error) {
	if in.CoreType == "" {
		in.CoreType = proto.CoreXray
	}
	if err := validateInboundInput(in); err != nil {
		return nil, err
	}

	var node model.Node
	if err := s.db.First(&node, in.NodeID).Error; err != nil {
		return nil, fmt.Errorf("node not found: %w", err)
	}

	// Enforce your workflow rule: the core must be installed on the node before creating an inbound on it.
	var nc model.NodeCore
	if err := s.db.Where("node_id = ? AND core_type = ? AND installed = ?", in.NodeID, in.CoreType, true).First(&nc).Error; err != nil {
		return nil, fmt.Errorf("core %q is not installed on node %q yet; install the core first", in.CoreType, node.Name)
	}

	var existing int64
	if err := s.db.Model(&model.Inbound{}).Where("node_id = ? AND port = ?", in.NodeID, in.Port).Count(&existing).Error; err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, fmt.Errorf("port %d is already used on node %q", in.Port, node.Name)
	}

	suffix, _ := crypto.RandomHex(4)
	tag := fmt.Sprintf("ib-%d-%d-%s", in.NodeID, in.Port, suffix)

	enable := true
	if in.Enable != nil {
		enable = *in.Enable
	}
	listen := strings.TrimSpace(in.Listen)
	if listen == "" {
		listen = "0.0.0.0"
	}
	remark := strings.TrimSpace(in.Remark)
	if remark == "" {
		remark = fmt.Sprintf("%s-%s-%d", node.Name, in.Protocol, in.Port)
	}

	ib := model.Inbound{
		NodeID:         in.NodeID,
		CoreType:       in.CoreType,
		Tag:            tag,
		Remark:         remark,
		Enable:         enable,
		Listen:         listen,
		Port:           in.Port,
		Protocol:       in.Protocol,
		Settings:       defaultJSONText(in.Settings, "{}"),
		StreamSettings: defaultJSONText(in.StreamSettings, `{"network":"tcp","security":"none"}`),
		Sniffing:       defaultJSONText(in.Sniffing, `{"enabled":true,"destOverride":["http","tls","quic"]}`),
	}
	if err := s.db.Create(&ib).Error; err != nil {
		return nil, err
	}
	ib.NodeName = node.Name

	if s.reconcile != nil {
		_ = s.reconcile.ReconcileNode(ctx, ib.NodeID)
	}
	return &ib, nil
}

func (s *InboundService) UpdateInbound(ctx context.Context, id uint, in InboundInput) (*model.Inbound, error) {
	var ib model.Inbound
	if err := s.db.First(&ib, id).Error; err != nil {
		return nil, err
	}
	if in.NodeID == 0 {
		in.NodeID = ib.NodeID
	}
	if in.CoreType == "" {
		in.CoreType = ib.CoreType
	}
	if err := validateInboundInput(in); err != nil {
		return nil, err
	}

	if in.Port != ib.Port || in.NodeID != ib.NodeID {
		var dup int64
		if err := s.db.Model(&model.Inbound{}).
			Where("node_id = ? AND port = ? AND id <> ?", in.NodeID, in.Port, ib.ID).
			Count(&dup).Error; err != nil {
			return nil, err
		}
		if dup > 0 {
			return nil, fmt.Errorf("port %d is already in use on target node", in.Port)
		}
	}

	oldNodeID := ib.NodeID
	ib.NodeID = in.NodeID
	ib.CoreType = in.CoreType
	if strings.TrimSpace(in.Remark) != "" {
		ib.Remark = strings.TrimSpace(in.Remark)
	}
	if in.Enable != nil {
		ib.Enable = *in.Enable
	}
	if strings.TrimSpace(in.Listen) != "" {
		ib.Listen = strings.TrimSpace(in.Listen)
	}
	ib.Port = in.Port
	ib.Protocol = in.Protocol
	if len(in.Settings) > 0 {
		ib.Settings = string(in.Settings)
	}
	if len(in.StreamSettings) > 0 {
		ib.StreamSettings = string(in.StreamSettings)
	}
	if len(in.Sniffing) > 0 {
		ib.Sniffing = string(in.Sniffing)
	}

	if err := s.db.Save(&ib).Error; err != nil {
		return nil, err
	}

	if s.reconcile != nil {
		if oldNodeID != ib.NodeID {
			_ = s.reconcile.ReconcileNode(ctx, oldNodeID)
		}
		_ = s.reconcile.ReconcileNode(ctx, ib.NodeID)
	}
	return &ib, nil
}

func (s *InboundService) DeleteInbound(ctx context.Context, id uint) error {
	var ib model.Inbound
	if err := s.db.First(&ib, id).Error; err != nil {
		return err
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("inbound_id = ?", id).Delete(&model.ClientInbound{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.Inbound{}, id).Error
	})
	if err != nil {
		return err
	}
	if s.reconcile != nil {
		_ = s.reconcile.ReconcileNode(ctx, ib.NodeID)
	}
	return nil
}

func defaultJSONText(raw json.RawMessage, fallback string) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return fallback
	}
	return trimmed
}
