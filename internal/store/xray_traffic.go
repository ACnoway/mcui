package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ACnoway/mcui/internal/xraytraffic"
)

var ErrXrayTrafficChanged = errors.New("Xray traffic sample changed")

const createXrayTraffic = `CREATE TABLE IF NOT EXISTS xray_traffic (
	node_id TEXT PRIMARY KEY,
	payload BLOB NOT NULL
)`

func (s *Store) RecordXrayTraffic(ctx context.Context, id, digest string, sample xraytraffic.Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	usage, err := readXrayTraffic(ctx, tx, id)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(usage.Observe(sample))
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO xray_traffic(node_id, payload)
		SELECT id, ? FROM nodes WHERE id = ? AND disabled = 0 AND `+nodeTokenHashSQL+` = ?
		ON CONFLICT(node_id) DO UPDATE SET payload = excluded.payload`, raw, id, digest)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) XrayTraffic(ctx context.Context, id string) (xraytraffic.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return readXrayTraffic(ctx, s.db, id)
}

// ResetXrayTraffic resets an observed counter without modifying Xray's
// cumulative counters. Matching the displayed sample prevents a repeated
// request from resetting later traffic.
func (s *Store) ResetXrayTraffic(ctx context.Context, nodeID, actor, key string, revision, sampledAt int64, expected xraytraffic.Bytes) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw, nodeRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT x.payload, n.payload FROM xray_traffic x JOIN nodes n ON n.id = x.node_id
		WHERE x.node_id = ? AND n.disabled = 0`, nodeID).Scan(&raw, &nodeRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var node Node
	if err := json.Unmarshal(nodeRaw, &node); err != nil {
		return err
	}
	if node.Inventory == nil || node.Inventory.Xray == nil || !node.Inventory.Xray.StatisticsActive ||
		node.Inventory.Xray.ConfigRevision != revision {
		return ErrXrayTrafficChanged
	}
	var usage xraytraffic.Usage
	if err := json.Unmarshal(raw, &usage); err != nil {
		return err
	}
	current, found := usage.Totals[key]
	if !found || expected == (xraytraffic.Bytes{}) || usage.Last.Revision != revision || usage.Last.At != sampledAt || current != expected {
		return ErrXrayTrafficChanged
	}
	usage.Totals[key] = xraytraffic.Bytes{}
	raw, err = json.Marshal(usage)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE xray_traffic SET payload = ? WHERE node_id = ?`, raw, nodeID); err != nil {
		return err
	}
	audit := Audit{At: time.Now().Unix(), Actor: actor, Action: "xray.traffic.reset",
		ResourceType: "node", Resource: nodeID, NodeID: nodeID, Outcome: "success"}
	raw, err = json.Marshal(audit)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(at, actor, resource_type, resource, action, outcome, payload)
		VALUES(?, ?, ?, ?, ?, ?, ?)`, audit.At, audit.Actor, audit.ResourceType, audit.Resource, audit.Action, audit.Outcome, raw); err != nil {
		return err
	}
	return tx.Commit()
}

func readXrayTraffic(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (xraytraffic.Usage, error) {
	var usage xraytraffic.Usage
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT payload FROM xray_traffic WHERE node_id = ?`, id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return usage, nil
		}
		return usage, err
	}
	err := json.Unmarshal(raw, &usage)
	return usage, err
}
