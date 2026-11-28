package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/master/dist"
	"github.com/ACnoway/mcui/internal/master/hub"
	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/internal/master/service"
	"github.com/ACnoway/mcui/internal/master/sub"
	"github.com/ACnoway/mcui/internal/master/tunnel"
	"github.com/ACnoway/mcui/pkg/crypto"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
)

const sessionCookieName = "mcui_session"

type Config struct {
	BinDir string
}

type Server struct {
	authSvc      *service.AuthService
	nodeSvc      *service.NodeService
	coreSvc      *service.CoreService
	inboundSvc   *service.InboundService
	clientSvc    *service.ClientService
	reconcileSvc *service.ReconcileService
	subSvc       *sub.Service
	tunnels      *tunnel.Manager
	wsHub        *hub.Hub
	cfg          Config
}

func New(
	gdb *gorm.DB,
	tunnels *tunnel.Manager,
	wsHub *hub.Hub,
	cfg Config,
) (*Server, error) {
	authSvc, err := service.NewAuthService(gdb)
	if err != nil {
		return nil, err
	}
	reconcileSvc := service.NewReconcileService(gdb, tunnels)
	nodeSvc := service.NewNodeService(gdb, tunnels, wsHub)
	coreSvc := service.NewCoreService(gdb, tunnels)
	inboundSvc := service.NewInboundService(gdb, reconcileSvc)
	clientSvc := service.NewClientService(gdb, reconcileSvc)
	subSvc := sub.NewService(gdb)

	s := &Server{
		authSvc:      authSvc,
		nodeSvc:      nodeSvc,
		coreSvc:      coreSvc,
		inboundSvc:   inboundSvc,
		clientSvc:    clientSvc,
		reconcileSvc: reconcileSvc,
		subSvc:       subSvc,
		tunnels:      tunnels,
		wsHub:        wsHub,
		cfg:          cfg,
	}

	if tunnels != nil {
		tunnels.SetHooks(
			func(nodeID uint, rep proto.AgentReport) {
				depletedNodes, err := nodeSvc.HandleAgentReport(nodeID, rep)
				if err != nil {
					return
				}
				// Reconcile when a core just finished installing or when a client depleted quota.
				for _, cs := range rep.Cores {
					if cs.Installed && (cs.ConfigHash == "" || cs.State == proto.CoreStopped) {
						go func(nid uint) {
							ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
							defer cancel()
							_ = reconcileSvc.ReconcileNode(ctx, nid)
						}(nodeID)
						break
					}
				}
				for _, dnID := range depletedNodes {
					go func(nid uint) {
						ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
						defer cancel()
						_ = reconcileSvc.ReconcileNode(ctx, nid)
					}(dnID)
				}
			},
			func(nodeID uint) {
				if wsHub != nil {
					if n, err := nodeSvc.GetNode(nodeID); err == nil {
						wsHub.Broadcast("node.online", n)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_ = reconcileSvc.ReconcileNode(ctx, nodeID)
			},
			func(nodeID uint) {
				if wsHub != nil {
					if n, err := nodeSvc.GetNode(nodeID); err == nil {
						wsHub.Broadcast("node.offline", n)
					}
				}
			},
		)
	}

	return s, nil
}

func (s *Server) CoreService() *service.CoreService           { return s.coreSvc }
func (s *Server) ReconcileService() *service.ReconcileService { return s.reconcileSvc }

func (s *Server) StartBackgroundLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcileSvc.ReconcileAllDirty(ctx)
			}
		}
	}()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public: Agent bootstrap script, binary download, enrollment, tunnel, and end-user subscriptions
	mux.HandleFunc("GET /install-agent.sh", s.handleInstallScript)
	mux.HandleFunc("GET /dl/{artifact}", s.handleDownloadAgentBinary)
	mux.HandleFunc("POST /api/agent/enroll", s.handleAgentEnroll)
	mux.HandleFunc("GET /api/agent/tunnel", s.handleAgentTunnel)
	mux.HandleFunc("GET /sub/{subId}", s.handleSubscription)

	// Public Auth endpoints
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)

	// Protected Admin API endpoints
	mux.HandleFunc("GET /api/auth/me", s.requireAdmin(s.handleMe))
	mux.HandleFunc("POST /api/auth/password", s.requireAdmin(s.handleChangePassword))
	mux.HandleFunc("GET /api/ws", s.requireAdmin(func(w http.ResponseWriter, r *http.Request, _ *model.User) {
		if s.wsHub != nil {
			s.wsHub.ServeWS(w, r)
		}
	}))

	mux.HandleFunc("GET /api/overview", s.requireAdmin(s.handleOverview))

	// Nodes & Remote Core Lifecycle
	mux.HandleFunc("GET /api/nodes", s.requireAdmin(s.handleListNodes))
	mux.HandleFunc("POST /api/nodes", s.requireAdmin(s.handleCreateNode))
	mux.HandleFunc("GET /api/nodes/{id}", s.requireAdmin(s.handleGetNode))
	mux.HandleFunc("PUT /api/nodes/{id}", s.requireAdmin(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.requireAdmin(s.handleDeleteNode))
	mux.HandleFunc("POST /api/nodes/{id}/enroll-token", s.requireAdmin(s.handleRotateEnrollToken))
	mux.HandleFunc("POST /api/nodes/{id}/reconcile", s.requireAdmin(s.handleReconcileNode))

	mux.HandleFunc("GET /api/cores/{coreType}/versions", s.requireAdmin(s.handleListCoreVersions))
	mux.HandleFunc("POST /api/nodes/{id}/cores/install", s.requireAdmin(s.handleInstallNodeCore))
	mux.HandleFunc("POST /api/nodes/{id}/cores/uninstall", s.requireAdmin(s.handleUninstallNodeCore))
	mux.HandleFunc("POST /api/nodes/{id}/cores/action", s.requireAdmin(s.handleNodeCoreAction))
	mux.HandleFunc("GET /api/nodes/{id}/cores/{coreType}/logs", s.requireAdmin(s.handleNodeCoreLogs))

	// Inbounds & Reality helpers
	mux.HandleFunc("GET /api/inbounds", s.requireAdmin(s.handleListInbounds))
	mux.HandleFunc("POST /api/inbounds", s.requireAdmin(s.handleCreateInbound))
	mux.HandleFunc("PUT /api/inbounds/{id}", s.requireAdmin(s.handleUpdateInbound))
	mux.HandleFunc("DELETE /api/inbounds/{id}", s.requireAdmin(s.handleDeleteInbound))
	mux.HandleFunc("POST /api/xray/reality-keys", s.requireAdmin(s.handleGenerateRealityKeys))

	// Central Clients (multi-node inbound bindings)
	mux.HandleFunc("GET /api/clients", s.requireAdmin(s.handleListClients))
	mux.HandleFunc("POST /api/clients", s.requireAdmin(s.handleCreateClient))
	mux.HandleFunc("PUT /api/clients/{id}", s.requireAdmin(s.handleUpdateClient))
	mux.HandleFunc("DELETE /api/clients/{id}", s.requireAdmin(s.handleDeleteClient))
	mux.HandleFunc("POST /api/clients/{id}/reset-traffic", s.requireAdmin(s.handleResetClientTraffic))
	mux.HandleFunc("GET /api/clients/{id}/links", s.requireAdmin(s.handleGetClientLinks))

	// Embedded SPA fallback
	mux.Handle("/", s.spaHandler())

	return mux
}

type adminHandler func(w http.ResponseWriter, r *http.Request, user *model.User)

func (s *Server) requireAdmin(next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tok string
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			tok = c.Value
		} else if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tok = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, proto.APIEnvelope[any]{Msg: "authentication required"})
			return
		}
		user, err := s.authSvc.VerifySession(tok)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, proto.APIEnvelope[any]{Msg: err.Error()})
			return
		}
		next(w, r, user)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	tok, user, err := s.authSvc.Login(body.Username, body.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		MaxAge:   7 * 24 * 3600,
	})
	writeJSON(w, http.StatusOK, proto.APIEnvelope[map[string]any]{
		Success: true,
		Obj: map[string]any{
			"token": tok,
			"user":  user,
		},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true})
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, user *model.User) {
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.User]{Success: true, Obj: user})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, user *model.User) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewUsername     string `json:"newUsername"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	if err := s.authSvc.ChangeCredentials(user.ID, body.CurrentPassword, body.NewUsername, body.NewPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true, Msg: "credentials updated; please sign in again"})
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request, _ *model.User) {
	nodes, _ := s.nodeSvc.ListNodes()
	inbounds, _ := s.inboundSvc.ListInbounds(0)
	clients, _ := s.clientSvc.ListClients()

	var onlineNodes, installedCores, runningCores int
	var netUpRate, netDownRate uint64
	for _, n := range nodes {
		if n.Online {
			onlineNodes++
			netUpRate += n.NetUpRate
			netDownRate += n.NetDownRate
		}
		for _, c := range n.Cores {
			if c.Installed {
				installedCores++
			}
			if c.State == proto.CoreRunning {
				runningCores++
			}
		}
	}

	var totalUp, totalDown int64
	var activeClients int
	for _, cl := range clients {
		totalUp += cl.Up
		totalDown += cl.Down
		if cl.Enable {
			activeClients++
		}
	}

	writeJSON(w, http.StatusOK, proto.APIEnvelope[map[string]any]{
		Success: true,
		Obj: map[string]any{
			"totalNodes":     len(nodes),
			"onlineNodes":    onlineNodes,
			"installedCores": installedCores,
			"runningCores":   runningCores,
			"totalInbounds":  len(inbounds),
			"totalClients":   len(clients),
			"activeClients":  activeClients,
			"netUpRate":      netUpRate,
			"netDownRate":    netDownRate,
			"totalTrafficUp": totalUp,
			"totalTrafficDn": totalDown,
		},
	})
}

func (s *Server) handleAgentTunnel(w http.ResponseWriter, r *http.Request) {
	node, err := s.nodeSvc.AuthenticateNodeToken(r.Header.Get("Authorization"))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	if err := s.tunnels.AcceptWebSocket(w, r, node.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	resp, err := s.nodeSvc.Enroll(req)
	if err != nil {
		writeJSON(w, http.StatusForbidden, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.EnrollResponse]{Success: true, Obj: *resp})
}

func (s *Server) handleListNodes(w http.ResponseWriter, _ *http.Request, _ *model.User) {
	nodes, err := s.nodeSvc.ListNodes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]model.Node]{Success: true, Obj: nodes})
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request, _ *model.User) {
	var in service.CreateNodeInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	created, err := s.nodeSvc.CreateNode(in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, proto.APIEnvelope[*service.NodeWithEnroll]{Success: true, Obj: created})
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	node, err := s.nodeSvc.GetNode(id)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.Node]{Success: true, Obj: node})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var in service.UpdateNodeInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	node, err := s.nodeSvc.UpdateNode(id, in)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.Node]{Success: true, Obj: node})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.nodeSvc.DeleteNode(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true})
}

func (s *Server) handleRotateEnrollToken(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	tok, err := s.nodeSvc.RotateEnrollToken(id, 0)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[map[string]string]{
		Success: true,
		Obj:     map[string]string{"enrollToken": tok},
	})
}

func (s *Server) handleReconcileNode(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.reconcileSvc.ReconcileNode(r.Context(), id); err != nil {
		writeJSON(w, http.StatusBadGateway, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true})
}

func (s *Server) handleListCoreVersions(w http.ResponseWriter, r *http.Request, _ *model.User) {
	ct := proto.CoreType(r.PathValue("coreType"))
	refresh := r.URL.Query().Get("refresh") == "1"
	vers, err := s.coreSvc.ListAvailableVersions(r.Context(), ct, refresh)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]string]{Success: true, Obj: vers})
}

func (s *Server) handleInstallNodeCore(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var in service.InstallNodeCoreInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	st, err := s.coreSvc.InstallOnNode(r.Context(), id, in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, proto.APIEnvelope[proto.CoreStatus]{Success: true, Obj: st})
}

func (s *Server) handleUninstallNodeCore(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		CoreType proto.CoreType `json:"coreType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	if body.CoreType == "" {
		body.CoreType = proto.CoreXray
	}
	st, err := s.coreSvc.UninstallOnNode(r.Context(), id, body.CoreType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.CoreStatus]{Success: true, Obj: st})
}

func (s *Server) handleNodeCoreAction(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var req proto.CoreActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	if req.CoreType == "" {
		req.CoreType = proto.CoreXray
	}
	st, err := s.coreSvc.ControlOnNode(r.Context(), id, req.CoreType, req.Action)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[proto.CoreStatus]{Success: true, Obj: st})
}

func (s *Server) handleNodeCoreLogs(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	ct := proto.CoreType(r.PathValue("coreType"))
	lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	logs, err := s.coreSvc.GetLogs(r.Context(), id, ct, lines)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]string]{Success: true, Obj: logs})
}

func (s *Server) handleListInbounds(w http.ResponseWriter, r *http.Request, _ *model.User) {
	var nodeID uint
	if raw := r.URL.Query().Get("nodeId"); raw != "" {
		if v, err := strconv.ParseUint(raw, 10, 32); err == nil {
			nodeID = uint(v)
		}
	}
	list, err := s.inboundSvc.ListInbounds(nodeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]model.Inbound]{Success: true, Obj: list})
}

func (s *Server) handleCreateInbound(w http.ResponseWriter, r *http.Request, _ *model.User) {
	var in service.InboundInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	ib, err := s.inboundSvc.CreateInbound(r.Context(), in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, proto.APIEnvelope[*model.Inbound]{Success: true, Obj: ib})
}

func (s *Server) handleUpdateInbound(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var in service.InboundInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	ib, err := s.inboundSvc.UpdateInbound(r.Context(), id, in)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.Inbound]{Success: true, Obj: ib})
}

func (s *Server) handleDeleteInbound(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.inboundSvc.DeleteInbound(r.Context(), id); err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true})
}

func (s *Server) handleGenerateRealityKeys(w http.ResponseWriter, _ *http.Request, _ *model.User) {
	kp, err := crypto.GenerateRealityKeyPair()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	shortID, _ := crypto.RandomHex(4)
	writeJSON(w, http.StatusOK, proto.APIEnvelope[map[string]string]{
		Success: true,
		Obj: map[string]string{
			"privateKey": kp.PrivateKey,
			"publicKey":  kp.PublicKey,
			"shortId":    shortID,
		},
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, _ *http.Request, _ *model.User) {
	list, err := s.clientSvc.ListClients()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[[]model.Client]{Success: true, Obj: list})
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request, _ *model.User) {
	var in service.ClientInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	cl, err := s.clientSvc.CreateClient(r.Context(), in)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, proto.APIEnvelope[*model.Client]{Success: true, Obj: cl})
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	var in service.ClientInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	cl, err := s.clientSvc.UpdateClient(r.Context(), id, in)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.Client]{Success: true, Obj: cl})
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	if err := s.clientSvc.DeleteClient(r.Context(), id); err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[any]{Success: true})
}

func (s *Server) handleResetClientTraffic(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	cl, err := s.clientSvc.ResetClientTraffic(r.Context(), id)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*model.Client]{Success: true, Obj: cl})
}

func (s *Server) handleGetClientLinks(w http.ResponseWriter, r *http.Request, _ *model.User) {
	id, ok := parseUintParam(w, r, "id")
	if !ok {
		return
	}
	cl, err := s.clientSvc.GetClient(id)
	if err != nil {
		writeGormErr(w, err)
		return
	}
	bundle, err := s.subSvc.BuildBySubID(cl.SubID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, proto.APIEnvelope[any]{Msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, proto.APIEnvelope[*sub.SubscriptionBundle]{Success: true, Obj: bundle})
}

func (s *Server) handleSubscription(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("subId")
	bundle, err := s.subSvc.BuildBySubID(subID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cl := bundle.Client
	var expireSec int64
	if cl.ExpiryTime > 0 {
		expireSec = cl.ExpiryTime / 1000
	}
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf(
		"upload=%d; download=%d; total=%d; expire=%d",
		cl.Up, cl.Down, cl.TotalBytes, expireSec,
	))
	w.Header().Set("Profile-Title", cl.Email)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.URL.Query().Get("format") == "raw" {
		_, _ = w.Write([]byte(strings.Join(bundle.Links, "\n")))
		return
	}
	_, _ = w.Write([]byte(bundle.RawB64))
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	masterOrigin := fmt.Sprintf("%s://%s", scheme, r.Host)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	script := fmt.Sprintf(`#!/usr/bin/env sh
set -eu

ENROLL_TOKEN=""
MASTER_URL="%s"
INSECURE_FLAG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --token) ENROLL_TOKEN="$2"; shift 2 ;;
    --master) MASTER_URL="$2"; shift 2 ;;
    --insecure) INSECURE_FLAG="--insecure"; shift 1 ;;
    *) shift 1 ;;
  esac
done

if [ -z "$ENROLL_TOKEN" ]; then
  echo "Error: --token <ENROLL_TOKEN> is required" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

mkdir -p /usr/local/bin /etc/mcui-agent /var/lib/mcui-agent
echo "Downloading mcui-agent (linux-${GO_ARCH}) from ${MASTER_URL}..."
curl -fsSL ${INSECURE_FLAG:+-k} "${MASTER_URL}/dl/mcui-agent-linux-${GO_ARCH}" -o /usr/local/bin/mcui-agent.tmp
chmod +x /usr/local/bin/mcui-agent.tmp
mv /usr/local/bin/mcui-agent.tmp /usr/local/bin/mcui-agent

cat >/etc/mcui-agent/agent.json <<EOF
{
  "masterUrl": "${MASTER_URL}",
  "enrollToken": "${ENROLL_TOKEN}",
  "dataDir": "/var/lib/mcui-agent",
  "insecureTls": $( [ -n "$INSECURE_FLAG" ] && echo "true" || echo "false" )
}
EOF
chmod 600 /etc/mcui-agent/agent.json

if command -v systemctl >/dev/null 2>&1; then
  cat >/etc/systemd/system/mcui-agent.service <<'UNIT'
[Unit]
Description=MCUI Zero-Port Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mcui-agent -config /etc/mcui-agent/agent.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now mcui-agent.service
  echo "mcui-agent installed and started (0 listening ports; no proxy cores installed yet)."
else
  echo "systemd not detected. Run manually: /usr/local/bin/mcui-agent -config /etc/mcui-agent/agent.json"
fi
`, masterOrigin)
	_, _ = w.Write([]byte(script))
}

func (s *Server) handleDownloadAgentBinary(w http.ResponseWriter, r *http.Request) {
	artifact := r.PathValue("artifact")
	trimmed := strings.TrimPrefix(artifact, "mcui-agent-")
	parts := strings.Split(trimmed, "-")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	goos, goarch := parts[0], parts[1]
	if goos != "linux" || (goarch != "amd64" && goarch != "arm64") {
		http.NotFound(w, r)
		return
	}
	binDir := s.cfg.BinDir
	if binDir == "" {
		binDir = "./bin"
	}
	candidates := []string{
		filepath.Join(binDir, fmt.Sprintf("mcui-agent-%s-%s", goos, goarch)),
		filepath.Join(binDir, "mcui-agent"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
	}
	http.Error(w, "agent binary not found on master (build bin/mcui-agent first)", http.StatusNotFound)
}

func (s *Server) spaHandler() http.Handler {
	fileServer := http.FileServer(http.FS(dist.Assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusNotFound, proto.APIEnvelope[any]{Msg: "endpoint not found"})
			return
		}
		cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanPath == "" {
			cleanPath = "index.html"
		}
		if f, err := fs.Stat(dist.Assets, cleanPath); err == nil && !f.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		indexBytes, err := fs.ReadFile(dist.Assets, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexBytes)
	})
}

func parseUintParam(w http.ResponseWriter, r *http.Request, name string) (uint, bool) {
	v, err := strconv.ParseUint(r.PathValue(name), 10, 32)
	if err != nil || v == 0 {
		writeJSON(w, http.StatusBadRequest, proto.APIEnvelope[any]{Msg: "invalid id"})
		return 0, false
	}
	return uint(v), true
}

func writeGormErr(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, gorm.ErrRecordNotFound) {
		status = http.StatusNotFound
	}
	writeJSON(w, status, proto.APIEnvelope[any]{Msg: err.Error()})
}

func writeJSON[T any](w http.ResponseWriter, code int, env proto.APIEnvelope[T]) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(env)
}
