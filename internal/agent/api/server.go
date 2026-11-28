package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ACnoway/mcui/internal/agent/core"
	"github.com/ACnoway/mcui/pkg/proto"
)

type Server struct {
	cores     *core.Manager
	onChanged func()
}

func NewServer(cores *core.Manager, onChanged func()) *Server {
	return &Server{cores: cores, onChanged: onChanged}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", s.handlePing)
	mux.HandleFunc("GET /v1/cores", s.handleListCores)
	mux.HandleFunc("POST /v1/cores/install", s.handleInstallCore)
	mux.HandleFunc("POST /v1/cores/uninstall", s.handleUninstallCore)
	mux.HandleFunc("POST /v1/cores/action", s.handleCoreAction)
	mux.HandleFunc("POST /v1/state/apply", s.handleApplyState)
	mux.HandleFunc("GET /v1/cores/logs", s.handleCoreLogs)
	return mux
}

func writeJSON[T any](w http.ResponseWriter, status int, env proto.APIEnvelope[T]) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (s *Server) notify() {
	if s.onChanged != nil {
		s.onChanged()
	}
}

func (s *Server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, proto.APIEnvelope[string]{Success: true, Obj: "pong"})
}

func (s *Server) handleListCores(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]proto.CoreStatus]{
		Success: true,
		Obj:     s.cores.AllStatuses(),
	})
}

func (s *Server) handleInstallCore(w http.ResponseWriter, r *http.Request) {
	var req proto.InstallCoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	drv, err := s.cores.Get(req.CoreType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}

	// Run asynchronously so large GitHub release downloads don't block the RPC stream,
	// while immediate heartbeat notifications stream progress back to the Master UI.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		s.notify()
		_ = drv.Install(ctx, req)
		s.notify()
	}()

	writeJSON(w, http.StatusAccepted, proto.APIEnvelope[proto.CoreStatus]{
		Success: true,
		Msg:     "installation started",
		Obj:     drv.Status(),
	})
}

func (s *Server) handleUninstallCore(w http.ResponseWriter, r *http.Request) {
	var req proto.UninstallCoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	drv, err := s.cores.Get(req.CoreType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	if err := drv.Uninstall(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	s.notify()
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.CoreStatus]{Success: true, Obj: drv.Status()})
}

func (s *Server) handleCoreAction(w http.ResponseWriter, r *http.Request) {
	var req proto.CoreActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	drv, err := s.cores.Get(req.CoreType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	switch req.Action {
	case "start":
		err = drv.Start(r.Context())
	case "stop":
		err = drv.Stop(r.Context())
	case "restart":
		err = drv.Restart(r.Context())
	default:
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: "unknown action"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	s.notify()
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.CoreStatus]{Success: true, Obj: drv.Status()})
}

func (s *Server) handleApplyState(w http.ResponseWriter, r *http.Request) {
	var spec proto.DesiredCoreSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	drv, err := s.cores.Get(spec.CoreType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	res, err := drv.ApplyState(r.Context(), spec)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	s.notify()
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.ApplyStateResponse]{Success: true, Obj: res})
}

func (s *Server) handleCoreLogs(w http.ResponseWriter, r *http.Request) {
	ct := proto.CoreType(r.URL.Query().Get("coreType"))
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if lines <= 0 {
		lines = 200
	}
	drv, err := s.cores.Get(ct)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]string]{
		Success: true,
		Obj:     drv.RecentLogs(lines),
	})
}
