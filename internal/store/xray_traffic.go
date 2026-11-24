package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/ACnoway/mcui/internal/xraytraffic"
)

const createXrayTraffic = `CREATE TABLE IF NOT EXISTS xray_traffic (
	node_id TEXT PRIMARY KEY,
	payload BLOB NOT NULL
)`

func (s *Store) RecordXrayTraffic(ctx context.Context, id, digest string, sample xraytraffic.Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	usage, err := readXrayTraffic(ctx, s.db, id)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(usage.Observe(sample))
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO xray_traffic(node_id, payload)
		SELECT id, ? FROM nodes WHERE id = ? AND disabled = 0 AND `+nodeTokenHashSQL+` = ?
		ON CONFLICT(node_id) DO UPDATE SET payload = excluded.payload`, raw, id, digest)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count != 1 {
		return ErrNotFound
	}
	return err
}

func (s *Store) XrayTraffic(ctx context.Context, id string) (xraytraffic.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return readXrayTraffic(ctx, s.db, id)
}

func readXrayTraffic(ctx context.Context, db *sql.DB, id string) (xraytraffic.Usage, error) {
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
