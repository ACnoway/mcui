package master

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/ACnoway/mcui/internal/checkpoint"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

const taskCheckpointTimeout = 35 * time.Second

type taskCheckpoint struct {
	machine checkpoint.Machine
}

// TaskCheckpointDigest binds both databases, including credentials, session
// lifecycle, audits, signed tasks, leases, controls and ACKs. Node heartbeats
// change only the excluded last-seen telemetry.
// The caller must hold exclusive ownership of both stores while hashing them.
func TaskCheckpointDigest(ctx context.Context, stateStore *store.Store, tasks *taskdispatch.Store) ([32]byte, error) {
	var digest [32]byte
	taskDigest, err := tasks.CheckpointDigest(ctx)
	if err != nil {
		return digest, fmt.Errorf("digest task store: %w", err)
	}
	hash := sha256.New()
	hash.Write([]byte("mcui:master-task-checkpoint:v1\x00"))
	hash.Write(taskDigest[:])
	err = stateStore.View(func(state store.State) error {
		for id, node := range state.Nodes {
			node.LastSeen = 0
			state.Nodes[id] = node
		}
		return json.NewEncoder(hash).Encode(state)
	})
	if err != nil {
		return digest, fmt.Errorf("digest panel store: %w", err)
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// Keep reservations and dispatch transitions serialized across the two SQLite
// stores even on a single Master without an external checkpoint.
func (s *Server) runWithTaskState(ctx context.Context, operation func() error) error {
	s.taskState.Lock()
	defer s.taskState.Unlock()

	gate := s.taskCheckpoint
	if gate == nil {
		return operation()
	}

	before, err := s.verifyTaskCheckpoint(ctx)
	if err != nil {
		return err
	}
	if err := operation(); err != nil {
		return err
	}

	// An HTTP client disconnect must not interrupt publication of a committed
	// mutation. An unfinished durable intent is reconciled on the next request.
	commitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), taskCheckpointTimeout)
	defer cancel()
	digest, err := TaskCheckpointDigest(commitCtx, s.store, s.taskRuntime.Store)
	if err != nil {
		return err
	}
	if digest == before.Digest {
		return nil
	}
	next := before
	next.Digest = digest
	next.Revision++
	if err := gate.machine.Journal.Begin(commitCtx, before, checkpoint.Intent{Previous: before, Next: next}); err != nil {
		return fmt.Errorf("persist Master checkpoint intent: %w", err)
	}
	return gate.machine.Recover(commitCtx)
}

func (s *Server) verifyTaskCheckpoint(ctx context.Context) (checkpoint.Record, error) {
	machine := s.taskCheckpoint.machine
	state, err := machine.Journal.Load(ctx)
	if err != nil {
		return checkpoint.Record{}, err
	}
	expected := state.Committed
	if state.Intent != nil {
		expected = state.Intent.Next
	}
	digest, err := TaskCheckpointDigest(ctx, s.store, s.taskRuntime.Store)
	if err != nil {
		return checkpoint.Record{}, err
	}
	// Validate a pending intent against the current stores before any CAS.
	if expected.Digest != digest {
		return checkpoint.Record{}, fmt.Errorf("%w: Master databases differ from the journal", checkpoint.ErrDenied)
	}
	if err := machine.Recover(ctx); err != nil {
		return checkpoint.Record{}, err
	}
	if expected.Revision == math.MaxUint64 {
		return checkpoint.Record{}, fmt.Errorf("%w: Master checkpoint revision exhausted", checkpoint.ErrDenied)
	}
	return expected, nil
}

// Register every API that reads or writes the two security databases through
// the guard. This includes GET handlers that refresh or expire sessions.
func (s *Server) handleAPI(pattern string, handler http.HandlerFunc) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if s.taskCheckpoint == nil && s.runtimeUpdates == nil && (s.taskRuntime == nil || s.taskRuntime.XrayInstallPolicy == nil) {
			handler(w, r)
			return
		}
		response := w
		if s.taskCheckpoint != nil {
			response = &checkpointResponse{header: make(http.Header)}
		}
		err := s.runWithTaskState(r.Context(), func() error {
			handler(response, r)
			return nil
		})
		if err != nil {
			if r.Context().Err() == nil {
				log.Printf("Master task checkpoint blocked %s: %v", pattern, err)
			}
			http.Error(w, "Master task checkpoint unavailable", http.StatusServiceUnavailable)
			return
		}
		if buffered, ok := response.(*checkpointResponse); ok {
			buffered.send(w)
		}
	})
}

// Buffer the response so credentials, leases and success acknowledgments
// become visible only after the independent checkpoint has committed.
type checkpointResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *checkpointResponse) Header() http.Header { return w.header }

func (w *checkpointResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *checkpointResponse) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.body.Write(p)
}

func (w *checkpointResponse) send(destination http.ResponseWriter) {
	for name, values := range w.header {
		destination.Header()[name] = values
	}
	w.WriteHeader(http.StatusOK)
	destination.WriteHeader(w.status)
	_, _ = destination.Write(w.body.Bytes())
}
