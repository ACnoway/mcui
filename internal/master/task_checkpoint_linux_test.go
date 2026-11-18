package master

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/checkpointjournal"
	"github.com/ACnoway/mcui/internal/checkpointstore"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

func TestTaskCheckpointRejectsCoordinatedDatabaseRestore(t *testing.T) {
	live := t.TempDir()
	older := t.TempDir()
	client := newTaskTestClientAt(t, live)
	journal, authority, initial := enrollTestCheckpoint(t, client)
	archive := func(dst string) {
		t.Helper()
		if err := store.Backup(filepath.Join(live, "mcui.db"), filepath.Join(dst, "mcui.db")); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(live, "tasks.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "tasks.db"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	archive(older)
	oldJournal, err := checkpointjournal.Create(filepath.Join(older, "journal.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = oldJournal.Close() })

	in := statusTaskRequest{RequestID: "checkpoint-request-123456", NodeID: client.nodeID, Core: "xray"}
	created := client.request(http.MethodPost, "/api/v1/admin/tasks", in, false)
	if created.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, body = %s", created.Code, created.Body)
	}
	lease := client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=1", nil, true)
	if lease.Code != http.StatusOK {
		t.Fatalf("lease status = %d, body = %s", lease.Code, lease.Body)
	}
	anchored, err := authority.Read(t.Context(), initial.Node, initial.Epoch, checkpoint.Challenge{1})
	if err != nil || anchored.Record.Revision != 2 {
		t.Fatalf("authority after issue and lease = %+v, err = %v", anchored, err)
	}

	fresh := t.TempDir()
	archive(fresh)
	openRestored := func(t *testing.T, dir string, local checkpoint.Journal) *Server {
		t.Helper()
		st, err := store.OpenExisting(filepath.Join(dir, "mcui.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		tasks, err := taskdispatch.Open(filepath.Join(dir, "tasks.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tasks.Close() })
		s := New(st, "", "")
		runtime := *client.server.taskRuntime
		runtime.Store = tasks
		runtime.Checkpoint = &checkpoint.Machine{Journal: local, Authority: authority}
		if err := s.ConfigureTaskRuntime(runtime); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := openRestored(t, fresh, journal).ReconcileTaskRuntime(); err != nil {
		t.Fatalf("fresh coordinated backup was rejected: %v", err)
	}
	for _, local := range []checkpoint.Journal{journal, oldJournal} {
		t.Run("old-journal="+strconv.FormatBool(local == oldJournal), func(t *testing.T) {
			restored := openRestored(t, older, local)
			if err := restored.ReconcileTaskRuntime(); !errors.Is(err, checkpoint.ErrDenied) {
				t.Fatalf("coordinated old restore should be denied, got %v", err)
			}
			probe := client
			probe.server = restored
			res := probe.request(http.MethodPost, "/api/v1/admin/tasks", in, false)
			if res.Code != http.StatusServiceUnavailable {
				t.Fatalf("status after restore = %d, body = %s", res.Code, res.Body)
			}
			if _, err := restored.taskRuntime.Store.GetRecord(in.RequestID); !errors.Is(err, taskdispatch.ErrNotFound) {
				t.Fatalf("denied request changed the task store: %v", err)
			}
		})
	}
	observed, err := authority.Read(t.Context(), initial.Node, initial.Epoch, anchored.Challenge)
	if err != nil || observed != anchored {
		t.Fatalf("restored databases changed authority: %+v, %v", observed, err)
	}
}

func TestTaskCheckpointRecoversLostCommitResponse(t *testing.T) {
	client := newTaskTestClient(t)
	journal, authority, initial := enrollTestCheckpoint(t, client)
	lost := &loseCheckpointReply{Authority: authority, drop: true}
	configureTestCheckpoint(t, client.server, journal, lost)
	in := statusTaskRequest{RequestID: "checkpoint-request-123456", NodeID: client.nodeID, Core: "xray"}
	reply := client.request(http.MethodPost, "/api/v1/admin/tasks", in, false)
	if reply.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfirmed commit returned %d, body = %s", reply.Code, reply.Body)
	}
	state, err := journal.Load(t.Context())
	if err != nil || state.Committed != initial || state.Intent == nil {
		t.Fatalf("no durable pending checkpoint: %+v, %v", state, err)
	}
	if err := client.server.ReconcileTaskRuntime(); err != nil {
		t.Fatalf("could not recover committed checkpoint: %v", err)
	}
	committed, err := journal.Load(t.Context())
	if err != nil || committed.Intent != nil || committed.Committed != state.Intent.Next {
		t.Fatalf("failed to recover checkpoint: %+v, %v", committed, err)
	}
	retry := client.request(http.MethodPost, "/api/v1/admin/tasks", in, false)
	if retry.Code != http.StatusCreated {
		t.Fatalf("retry returned %d, body = %s", retry.Code, retry.Body)
	}
	refs, err := client.server.taskRuntime.Store.ListTaskReferences()
	if err != nil || len(refs) != 1 || refs[0].TaskID != in.RequestID {
		t.Fatalf("retry changed the task sequence: %+v, %v", refs, err)
	}
}

func TestTaskCheckpointRejectsIntentWithoutMatchingDatabases(t *testing.T) {
	client := newTaskTestClient(t)
	journal, authority, initial := enrollTestCheckpoint(t, client)
	next := initial
	next.Revision++
	next.Digest[0] ^= 1
	if err := journal.Begin(t.Context(), initial, checkpoint.Intent{Previous: initial, Next: next}); err != nil {
		t.Fatal(err)
	}
	if err := client.server.ReconcileTaskRuntime(); !errors.Is(err, checkpoint.ErrDenied) {
		t.Fatalf("intent without matching databases should be denied, got %v", err)
	}
	observed, err := authority.Read(t.Context(), initial.Node, initial.Epoch, checkpoint.Challenge{1})
	if err != nil || observed.Record != initial {
		t.Fatalf("mismatched intent reached authority: %+v, %v", observed, err)
	}
}

func enrollTestCheckpoint(t *testing.T, client taskTestClient) (*checkpointjournal.Journal, *checkpointstore.Store, checkpoint.Record) {
	t.Helper()
	digest, err := TaskCheckpointDigest(t.Context(), client.store, client.server.taskRuntime.Store)
	if err != nil {
		t.Fatal(err)
	}
	initial := checkpoint.Record{Node: "test-master", Epoch: 1, Digest: digest}
	dir := t.TempDir()
	journal, err := checkpointjournal.Create(filepath.Join(dir, "journal.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	authority, err := checkpointstore.Create(filepath.Join(dir, "authority.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	configureTestCheckpoint(t, client.server, journal, authority)
	if err := client.server.ReconcileTaskRuntime(); err != nil {
		t.Fatal(err)
	}
	return journal, authority, initial
}

func configureTestCheckpoint(t *testing.T, s *Server, journal checkpoint.Journal, authority checkpoint.Authority) {
	t.Helper()
	runtime := *s.taskRuntime
	runtime.Checkpoint = &checkpoint.Machine{Journal: journal, Authority: authority}
	if err := s.ConfigureTaskRuntime(runtime); err != nil {
		t.Fatal(err)
	}
}

type loseCheckpointReply struct {
	checkpoint.Authority
	drop bool
}

func (a *loseCheckpointReply) CompareAndSwap(ctx context.Context, previous, next checkpoint.Record, c checkpoint.Challenge) (checkpoint.Observation, error) {
	observed, err := a.Authority.CompareAndSwap(ctx, previous, next, c)
	if err == nil && a.drop {
		a.drop = false
		return checkpoint.Observation{}, errors.New("simulated lost checkpoint reply")
	}
	return observed, err
}
