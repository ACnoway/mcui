package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/pkg/crypto"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ClientService struct {
	db        *gorm.DB
	reconcile *ReconcileService
}

func NewClientService(gdb *gorm.DB, reconcile *ReconcileService) *ClientService {
	return &ClientService{db: gdb, reconcile: reconcile}
}

type ClientInput struct {
	Email      string `json:"email"`
	SubID      string `json:"subId"`
	UUID       string `json:"uuid"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	TotalBytes int64  `json:"totalBytes"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     *bool  `json:"enable,omitempty"`
	Comment    string `json:"comment"`
	InboundIDs []uint `json:"inboundIds"`
}

func validateIdentifier(label, val string) error {
	if val == "" || val == "." || val == ".." {
		return fmt.Errorf("%s is required", label)
	}
	for _, r := range val {
		if r == '/' || r == '\\' || r < 0x20 || unicode.IsSpace(r) {
			return fmt.Errorf("%s contains invalid characters", label)
		}
	}
	return nil
}

func (s *ClientService) ListClients() ([]model.Client, error) {
	var clients []model.Client
	if err := s.db.Order("id ASC").Find(&clients).Error; err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return clients, nil
	}

	var links []model.ClientInbound
	if err := s.db.Order("inbound_id ASC").Find(&links).Error; err != nil {
		return nil, err
	}
	byClient := make(map[uint][]uint, len(clients))
	for _, lk := range links {
		byClient[lk.ClientID] = append(byClient[lk.ClientID], lk.InboundID)
	}
	for i := range clients {
		clients[i].InboundIDs = byClient[clients[i].ID]
		if clients[i].InboundIDs == nil {
			clients[i].InboundIDs = []uint{}
		}
	}
	return clients, nil
}

func (s *ClientService) GetClient(id uint) (*model.Client, error) {
	var cl model.Client
	if err := s.db.First(&cl, id).Error; err != nil {
		return nil, err
	}
	var ids []uint
	_ = s.db.Model(&model.ClientInbound{}).Where("client_id = ?", cl.ID).Order("inbound_id ASC").Pluck("inbound_id", &ids).Error
	if ids == nil {
		ids = []uint{}
	}
	cl.InboundIDs = ids
	return &cl, nil
}

func (s *ClientService) CreateClient(ctx context.Context, in ClientInput) (*model.Client, error) {
	email := strings.TrimSpace(in.Email)
	if err := validateIdentifier("email", email); err != nil {
		return nil, err
	}
	subID := strings.TrimSpace(in.SubID)
	if subID == "" {
		subID, _ = crypto.RandomHex(8)
	}
	if err := validateIdentifier("subId", subID); err != nil {
		return nil, err
	}

	uid := strings.TrimSpace(in.UUID)
	if uid == "" {
		uid = uuid.NewString()
	}
	pwd := strings.TrimSpace(in.Password)
	if pwd == "" {
		pwd, _ = crypto.RandomHex(12)
	}
	enable := true
	if in.Enable != nil {
		enable = *in.Enable
	}

	inboundIDs := dedupeUints(in.InboundIDs)
	affectedNodes, err := s.resolveNodesForInbounds(inboundIDs)
	if err != nil {
		return nil, err
	}

	cl := model.Client{
		Email:      email,
		SubID:      subID,
		UUID:       uid,
		Password:   pwd,
		Flow:       strings.TrimSpace(in.Flow),
		TotalBytes: in.TotalBytes,
		ExpiryTime: in.ExpiryTime,
		Enable:     enable,
		Comment:    strings.TrimSpace(in.Comment),
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&cl).Error; err != nil {
			return err
		}
		for _, ibID := range inboundIDs {
			if err := tx.Create(&model.ClientInbound{ClientID: cl.ID, InboundID: ibID}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	cl.InboundIDs = inboundIDs

	if s.reconcile != nil && len(affectedNodes) > 0 {
		for _, nID := range affectedNodes {
			_ = s.reconcile.ReconcileNode(ctx, nID)
		}
	}
	return &cl, nil
}

func (s *ClientService) UpdateClient(ctx context.Context, id uint, in ClientInput) (*model.Client, error) {
	var cl model.Client
	if err := s.db.First(&cl, id).Error; err != nil {
		return nil, err
	}

	var prevInboundIDs []uint
	_ = s.db.Model(&model.ClientInbound{}).Where("client_id = ?", id).Pluck("inbound_id", &prevInboundIDs).Error
	prevNodes, _ := s.resolveNodesForInbounds(prevInboundIDs)

	if email := strings.TrimSpace(in.Email); email != "" {
		if err := validateIdentifier("email", email); err != nil {
			return nil, err
		}
		cl.Email = email
	}
	if subID := strings.TrimSpace(in.SubID); subID != "" {
		if err := validateIdentifier("subId", subID); err != nil {
			return nil, err
		}
		cl.SubID = subID
	}
	if uid := strings.TrimSpace(in.UUID); uid != "" {
		cl.UUID = uid
	}
	if pwd := strings.TrimSpace(in.Password); pwd != "" {
		cl.Password = pwd
	}
	cl.Flow = strings.TrimSpace(in.Flow)
	cl.TotalBytes = in.TotalBytes
	cl.ExpiryTime = in.ExpiryTime
	cl.Comment = strings.TrimSpace(in.Comment)
	if in.Enable != nil {
		cl.Enable = *in.Enable
	}

	nextInboundIDs := dedupeUints(in.InboundIDs)
	nextNodes, err := s.resolveNodesForInbounds(nextInboundIDs)
	if err != nil {
		return nil, err
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&cl).Error; err != nil {
			return err
		}
		if in.InboundIDs != nil {
			if err := tx.Where("client_id = ?", cl.ID).Delete(&model.ClientInbound{}).Error; err != nil {
				return err
			}
			for _, ibID := range nextInboundIDs {
				if err := tx.Create(&model.ClientInbound{ClientID: cl.ID, InboundID: ibID}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if in.InboundIDs != nil {
		cl.InboundIDs = nextInboundIDs
	} else {
		cl.InboundIDs = prevInboundIDs
	}

	if s.reconcile != nil {
		allNodes := dedupeUints(append(prevNodes, nextNodes...))
		for _, nID := range allNodes {
			_ = s.reconcile.ReconcileNode(ctx, nID)
		}
	}
	return &cl, nil
}

func (s *ClientService) ResetClientTraffic(ctx context.Context, id uint) (*model.Client, error) {
	var cl model.Client
	if err := s.db.First(&cl, id).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&model.Client{}).Where("id = ?", id).Updates(map[string]any{
		"up":     0,
		"down":   0,
		"enable": true,
	}).Error; err != nil {
		return nil, err
	}

	var inboundIDs []uint
	_ = s.db.Model(&model.ClientInbound{}).Where("client_id = ?", id).Pluck("inbound_id", &inboundIDs).Error
	nodes, _ := s.resolveNodesForInbounds(inboundIDs)
	if s.reconcile != nil {
		for _, nID := range nodes {
			_ = s.reconcile.ReconcileNode(ctx, nID)
		}
	}
	return s.GetClient(id)
}

func (s *ClientService) DeleteClient(ctx context.Context, id uint) error {
	var inboundIDs []uint
	_ = s.db.Model(&model.ClientInbound{}).Where("client_id = ?", id).Pluck("inbound_id", &inboundIDs).Error
	nodes, _ := s.resolveNodesForInbounds(inboundIDs)

	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("client_id = ?", id).Delete(&model.ClientInbound{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&model.Client{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		return err
	}
	if s.reconcile != nil {
		for _, nID := range nodes {
			_ = s.reconcile.ReconcileNode(ctx, nID)
		}
	}
	return nil
}

func (s *ClientService) resolveNodesForInbounds(inboundIDs []uint) ([]uint, error) {
	if len(inboundIDs) == 0 {
		return nil, nil
	}
	var inbounds []model.Inbound
	if err := s.db.Select("id, node_id").Where("id IN ?", inboundIDs).Find(&inbounds).Error; err != nil {
		return nil, err
	}
	if len(inbounds) != len(inboundIDs) {
		return nil, errors.New("one or more selected inbounds do not exist")
	}
	nodes := make([]uint, 0, len(inbounds))
	for _, ib := range inbounds {
		nodes = append(nodes, ib.NodeID)
	}
	return dedupeUints(nodes), nil
}

func dedupeUints(in []uint) []uint {
	seen := make(map[uint]struct{}, len(in))
	out := make([]uint, 0, len(in))
	for _, v := range in {
		if v == 0 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
