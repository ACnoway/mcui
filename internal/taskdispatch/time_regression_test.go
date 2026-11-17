package taskdispatch

import (
	"errors"
	"testing"
	"time"
)

func TestLeaseRejectsUnrepresentableClockWithoutMutation(t *testing.T) {
	s, _ := newStore(t)
	raw, key := signed(t)
	if err := s.Provision("node-001", 1, raw, "test-key", key); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC), time.Unix(0, 9223372036854775807).Add(-30 * time.Second)} {
		if _, err := s.Lease("node-001", now, "test-key", key); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unrepresentable %v accepted: %v", now, err)
		}
		var id, deadline any
		if err := s.db.QueryRow(`SELECT lease_id,lease_deadline FROM tasks`).Scan(&id, &deadline); err != nil {
			t.Fatal(err)
		}
		if id != nil || deadline != nil {
			t.Fatalf("invalid clock mutated lease: %v %v", id, deadline)
		}
	}
}
