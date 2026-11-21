package store

import (
	"context"
	"encoding/json"
)

const nodeTokenHashSQL = `json_extract(CAST(payload AS TEXT), '$.node_token_hash')`
const createNodeTokenIndex = `CREATE INDEX IF NOT EXISTS nodes_active_token_idx ON nodes (` + nodeTokenHashSQL + `) WHERE disabled = 0`
const findNodeTokenSQL = `SELECT id, payload FROM nodes WHERE disabled = 0 AND ` + nodeTokenHashSQL + ` = ? LIMIT 2`

func (s *Store) NodeByTokenHash(ctx context.Context, digest string) (Node, error) {
	if digest == "" {
		return Node{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, findNodeTokenSQL, digest)
	if err != nil {
		return Node{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Node{}, err
		}
		return Node{}, ErrNotFound
	}
	var id string
	var raw []byte
	if err := rows.Scan(&id, &raw); err != nil {
		return Node{}, err
	}
	if rows.Next() {
		return Node{}, ErrNotFound
	}
	if err := rows.Err(); err != nil {
		return Node{}, err
	}
	var node Node
	if err := json.Unmarshal(raw, &node); err != nil {
		return Node{}, err
	}
	if node.ID != id || node.Disabled || node.TokenHash != digest {
		return Node{}, ErrNotFound
	}
	return node, nil
}

func (s *Store) RecordNodeHeartbeat(ctx context.Context, id, digest string, seen int64) error {
	if id == "" || digest == "" {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.ExecContext(ctx, `UPDATE nodes
		SET last_seen = MAX(last_seen, ?), payload = CAST(json_set(CAST(payload AS TEXT), '$.last_seen', MAX(last_seen, ?)) AS BLOB)
		WHERE id = ? AND disabled = 0 AND `+nodeTokenHashSQL+` = ?`, seen, seen, id, digest)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrNotFound
	}
	return nil
}
