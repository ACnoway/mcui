package taskdispatch

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
)

// CheckpointDigest hashes the complete logical delivery state in a consistent
// read transaction. Physical page layout and SQLite journal files can differ
// between a database and its backup.
func (s *Store) CheckpointDigest(ctx context.Context) ([32]byte, error) {
	var digest [32]byte
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return digest, err
	}
	defer tx.Rollback()

	hash := sha256.New()
	enc := json.NewEncoder(hash)
	for _, table := range []struct{ name, query string }{
		{"tasks", `SELECT task_id,node_id,sequence,raw,key_id,active,lease_id,lease_deadline FROM tasks ORDER BY task_id`},
		{"controls", `SELECT task_id,kind,raw FROM task_controls ORDER BY task_id`},
		{"acks", `SELECT task_id,status_version,node_id,sequence,status,result FROM acks ORDER BY task_id,status_version`},
	} {
		if err := enc.Encode(table.name); err != nil {
			return digest, err
		}
		if err := hashRows(ctx, tx, enc, table.query); err != nil {
			return digest, err
		}
	}
	copy(digest[:], hash.Sum(nil))
	return digest, tx.Commit()
}

func hashRows(ctx context.Context, tx *sql.Tx, enc *json.Encoder, query string) error {
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	values := make([]any, len(columns))
	fields := make([]any, len(columns))
	for i := range fields {
		fields[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(fields...); err != nil {
			return err
		}
		if err := enc.Encode(values); err != nil {
			return err
		}
	}
	return rows.Err()
}
