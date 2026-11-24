package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ACnoway/mcui/internal/xraytraffic"
)

func TestVersionFourMigrationIndexesActiveNodeTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodes.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		st.Nodes["node-a"] = Node{ID: "node-a", TokenHash: "digest-a", LastSeen: 10}
		st.Nodes["node-b"] = Node{ID: "node-b", TokenHash: "digest-b", LastSeen: 20}
		st.Audits = append(st.Audits, Audit{Action: "original"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DROP TABLE xray_traffic; DROP TABLE xray_clients; DROP INDEX nodes_active_token_idx; UPDATE schema_migrations SET version = 4`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if version, err := VerifyDatabase(path); err != nil || version != schemaVersion {
		t.Fatalf("verify migrated database version=%d: %v", version, err)
	}

	ctx := t.Context()
	var id, parent, unused int
	var plan string
	if err := s.db.QueryRowContext(ctx, "EXPLAIN QUERY PLAN "+findNodeTokenSQL, "digest-a").
		Scan(&id, &parent, &unused, &plan); err != nil || !strings.Contains(plan, "nodes_active_token_idx") {
		t.Fatalf("lookup query plan: %q, %v", plan, err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER protect_audit BEFORE DELETE ON audit_logs
		BEGIN SELECT RAISE(ABORT, 'heartbeat rewrote audit'); END`); err != nil {
		t.Fatal(err)
	}
	for _, seen := range []int64{30, 25} {
		if err := s.RecordNodeHeartbeat(ctx, "node-a", "digest-a", seen, nil); err != nil {
			t.Fatal(err)
		}
	}
	assertNodeSeen(t, s, ctx, "digest-a", "node-a", 30)
	assertNodeSeen(t, s, ctx, "digest-b", "node-b", 20)
	if _, err := s.db.Exec("DROP TRIGGER protect_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		a := st.Nodes["node-a"]
		a.TokenHash = "digest-b"
		st.Nodes[a.ID] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeByTokenHash(ctx, "digest-b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ambiguous token was accepted: %v", err)
	}
	if err := s.RecordNodeHeartbeat(ctx, "node-a", "digest-a", 40, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotated token updated heartbeat: %v", err)
	}
	if err := s.Update(func(st *State) error {
		a := st.Nodes["node-a"]
		a.Disabled = true
		st.Nodes[a.ID] = a
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertNodeSeen(t, s, ctx, "digest-b", "node-b", 20)
	if err := s.RecordNodeHeartbeat(ctx, "node-a", "digest-b", 40, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled node updated heartbeat: %v", err)
	}
}

func assertNodeSeen(t *testing.T, s *Store, ctx context.Context, digest, id string, seen int64) {
	t.Helper()
	node, err := s.NodeByTokenHash(ctx, digest)
	if err != nil || node.ID != id || node.LastSeen != seen {
		t.Fatalf("lookup returned node %q, seen %d, error %v", node.ID, node.LastSeen, err)
	}
}

func TestXrayTrafficSurvivesNodeUpdates(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := t.Context()
	const id = "node-a"
	const token = "digest-a"
	if err := s.Update(func(st *State) error {
		st.Nodes[id] = Node{ID: id, TokenHash: token}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const key = "outbound:allowed"
	sample := xraytraffic.Sample{Revision: 1, Epoch: strings.Repeat("a", 64), At: 100,
		Counters: map[string]xraytraffic.Bytes{key: {Up: 12, Down: 34}}}
	if err := s.RecordXrayTraffic(ctx, id, token, sample); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error {
		row := st.Nodes[id]
		row.Name, row.TokenHash = "renamed", "digest-b"
		st.Nodes[id] = row
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sample.At++
	sample.Counters[key] = xraytraffic.Bytes{Up: 99, Down: 99}
	if err := s.RecordXrayTraffic(ctx, id, token, sample); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotated token recorded usage: %v", err)
	}
	usage, err := s.XrayTraffic(ctx, id)
	if err != nil || usage.Totals[key] != (xraytraffic.Bytes{Up: 12, Down: 34}) {
		t.Fatalf("node update lost or changed usage: %+v (%v)", usage, err)
	}
}
