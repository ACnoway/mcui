package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
)

type ReconcileService struct {
	db      *gorm.DB
	tunnels *tunnel.Manager
}

func NewReconcileService(gdb *gorm.DB, tunnels *tunnel.Manager) *ReconcileService {
	return &ReconcileService{db: gdb, tunnels: tunnels}
}

// BuildDesiredSpec assembles the exact declarative state for a given Node and CoreType,
// filtering to enabled inbounds and active (enabled, within quota, unexpired) attached clients.
func (s *ReconcileService) BuildDesiredSpec(nodeID uint, coreType proto.CoreType) (proto.DesiredCoreSpec, error) {
	var inbounds []model.Inbound
	if err := s.db.Where("node_id = ? AND core_type = ? AND enable = ?", nodeID, coreType, true).
		Order("id ASC").
		Find(&inbounds).Error; err != nil {
		return proto.DesiredCoreSpec{}, err
	}

	spec := proto.DesiredCoreSpec{
		CoreType: coreType,
		Inbounds: make([]proto.InboundSpec, 0, len(inbounds)),
	}
	if len(inbounds) == 0 {
		return spec, nil
	}

	ibIDs := make([]uint, len(inbounds))
	for i, ib := range inbounds {
		ibIDs[i] = ib.ID
	}

	var links []model.ClientInbound
	if err := s.db.Where("inbound_id IN ?", ibIDs).Order("client_id ASC").Find(&links).Error; err != nil {
		return proto.DesiredCoreSpec{}, err
	}

	clientIDSet := make(map[uint]struct{}, len(links))
	for _, lk := range links {
		clientIDSet[lk.ClientID] = struct{}{}
	}

	activeClients := make(map[uint]model.Client, len(clientIDSet))
	if len(clientIDSet) > 0 {
		cids := make([]uint, 0, len(clientIDSet))
		for cid := range clientIDSet {
			cids = append(cids, cid)
		}
		var clients []model.Client
		if err := s.db.Where("id IN ? AND enable = ?", cids, true).Find(&clients).Error; err != nil {
			return proto.DesiredCoreSpec{}, err
		}
		now := time.Now().UnixMilli()
		for _, cl := range clients {
			if cl.TotalBytes > 0 && (cl.Up+cl.Down) >= cl.TotalBytes {
				continue
			}
			if cl.ExpiryTime > 0 && now >= cl.ExpiryTime {
				continue
			}
			activeClients[cl.ID] = cl
		}
	}

	linksByInbound := make(map[uint][]model.ClientInbound, len(inbounds))
	for _, lk := range links {
		linksByInbound[lk.InboundID] = append(linksByInbound[lk.InboundID], lk)
	}

	for _, ib := range inbounds {
		users := make([]proto.InboundUserSpec, 0, len(linksByInbound[ib.ID]))
		for _, lk := range linksByInbound[ib.ID] {
			cl, ok := activeClients[lk.ClientID]
			if !ok {
				continue
			}
			flow := cl.Flow
			if lk.FlowOverride != "" {
				flow = lk.FlowOverride
			}
			users = append(users, proto.InboundUserSpec{
				Email:    cl.Email,
				UUID:     cl.UUID,
				Password: cl.Password,
				Flow:     flow,
			})
		}

		spec.Inbounds = append(spec.Inbounds, proto.InboundSpec{
			Tag:            ib.Tag,
			Protocol:       ib.Protocol,
			Listen:         ib.Listen,
			Port:           ib.Port,
			Settings:       rawOrNil(ib.Settings),
			StreamSettings: rawOrNil(ib.StreamSettings),
			Sniffing:       rawOrNil(ib.Sniffing),
			Users:          users,
		})
	}

	return spec, nil
}

// ReconcileNode pushes all installed core states to the target node if online,
// or marks the node ConfigDirty so it converges automatically upon reconnect.
func (s *ReconcileService) ReconcileNode(ctx context.Context, nodeID uint) error {
	if s.tunnels == nil || !s.tunnels.IsOnline(nodeID) {
		return s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", true).Error
	}

	var cores []model.NodeCore
	if err := s.db.Where("node_id = ? AND installed = ?", nodeID, true).Find(&cores).Error; err != nil {
		return err
	}
	if len(cores) == 0 {
		return s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", false).Error
	}

	var firstErr error
	for _, nc := range cores {
		spec, err := s.BuildDesiredSpec(nodeID, nc.CoreType)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		_, applyErr := s.tunnels.ApplyState(pctx, nodeID, spec)
		cancel()
		if applyErr != nil {
			firstErr = errors.Join(firstErr, applyErr)
		}
	}

	if firstErr != nil {
		_ = s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", true).Error
		return firstErr
	}
	return s.db.Model(&model.Node{}).Where("id = ?", nodeID).Update("config_dirty", false).Error
}

func (s *ReconcileService) ReconcileAllDirty(ctx context.Context) {
	var dirtyIDs []uint
	if err := s.db.Model(&model.Node{}).Where("config_dirty = ? AND enabled = ?", true, true).Pluck("id", &dirtyIDs).Error; err != nil {
		return
	}
	for _, id := range dirtyIDs {
		if s.tunnels != nil && s.tunnels.IsOnline(id) {
			_ = s.ReconcileNode(ctx, id)
		}
	}
}

func rawOrNil(text string) json.RawMessage {
	if text == "" {
		return nil
	}
	return json.RawMessage(text)
}
