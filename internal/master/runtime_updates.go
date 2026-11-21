package master

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/runtimeupdate"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/taskdispatch"
)

type RuntimeUpdatePolicy struct {
	ReleaseKey       []byte            `json:"release_key"`
	AuthorizationKey []byte            `json:"authorization_key"`
	ArchiveDir       string            `json:"archive_dir"`
	NodeTokens       map[string]string `json:"node_token_sha256"`
}

func (s *Server) ConfigureRuntimeUpdates(policy RuntimeUpdatePolicy) error {
	if s.taskCheckpoint == nil || s.taskRuntime == nil || s.taskRuntime.TrustedNow == nil {
		return errors.New("runtime updates require the independent Master checkpoint and trusted clock")
	}
	if len(policy.ReleaseKey) != ed25519.PublicKeySize || len(policy.AuthorizationKey) != ed25519.PublicKeySize ||
		ed25519.PublicKey(policy.ReleaseKey).Equal(ed25519.PublicKey(policy.AuthorizationKey)) ||
		!filepath.IsAbs(policy.ArchiveDir) || len(policy.NodeTokens) == 0 {
		return errors.New("invalid runtime update policy keys, archive directory or node credentials")
	}
	for _, key := range []ed25519.PublicKey{policy.ReleaseKey, policy.AuthorizationKey} {
		xray := s.taskRuntime.XrayInstallPolicy
		if s.taskRuntime.PublicKey.Equal(key) || xray != nil && xray.UsesPublicKey(key) {
			return errors.New("runtime signing keys must be separate from task signing keys")
		}
	}
	if info, err := os.Lstat(policy.ArchiveDir); err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return errors.New("runtime archive directory must be a directory without group or other write access")
	}
	used := map[string]bool{}
	for node, digest := range policy.NodeTokens {
		if !security.ValidNodeID(node) || !runtimeupdate.ValidDigest(digest) || used[digest] {
			return errors.New("invalid or duplicate runtime supervisor credential")
		}
		used[digest] = true
	}
	s.runtimeUpdates = &policy
	return nil
}

var errRuntimeBusy = errors.New("runtime update or task already reserved for node")
var errRuntimeScope = errors.New("runtime update outside current scope")

func runtimeUpdateReserved(st *store.State, nodeID string, now time.Time) bool {
	for _, entry := range st.RuntimeUpdates {
		if entry.NodeID == nodeID && (entry.Status == runtimeupdate.Delivered ||
			entry.Status == runtimeupdate.Queued && now.Before(entry.ExpiresAt)) {
			return true
		}
	}
	return false
}

func decodeRuntimeRequest(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst, json.RejectUnknownMembers(true))
}

func (s *Server) createRuntimeUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	if ctx.Admin.Role != "security_admin" {
		http.NotFound(w, r)
		return
	}
	policy := s.runtimeUpdates
	if r.TLS == nil || policy == nil {
		http.Error(w, "remote runtime update unavailable", http.StatusServiceUnavailable)
		return
	}
	var input struct {
		Package runtimeupdate.Package `json:"package"`
		MFACode string                `json:"mfa_code"`
	}
	if decodeRuntimeRequest(w, r, runtimeupdate.MaxPackageJSON, &input) != nil {
		http.Error(w, "invalid signed runtime update package", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, input.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	auth, archive, expiry, err := input.Package.Verify(policy.ReleaseKey, policy.AuthorizationKey)
	if err != nil {
		http.Error(w, "runtime release or authorization signature rejected", http.StatusBadRequest)
		return
	}
	if auth.NodeID != r.PathValue("node") {
		http.Error(w, "runtime update is signed for a different node", http.StatusBadRequest)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	if auth.ExpiresAt.Before(expiry) {
		expiry = auth.ExpiresAt
	}
	entry := store.RuntimeUpdate{
		ID: input.Package.ID(), NodeID: auth.NodeID, Sequence: auth.Sequence, Version: auth.Version,
		Architecture: auth.Architecture, ArchiveSHA256: archive.SHA256, ArchiveLength: archive.Length,
		ExpectedPair: auth.CurrentPair, ExpiresAt: expiry, Status: runtimeupdate.Queued,
		Package: &input.Package,
	}
	status := http.StatusCreated
	err = s.store.Update(func(st *store.State) error {
		node := st.Nodes[auth.NodeID]
		if !node.Enrolled || node.Disabled || policy.NodeTokens[auth.NodeID] == "" || !canManageNode(st.Admins[ctx.Admin.ID], node) {
			return errRuntimeScope
		}
		if old, ok := st.RuntimeUpdates[entry.ID]; ok {
			entry, status = old, http.StatusOK
			return nil
		}
		if !auth.MatchesTime(now, expiry) || runtimeUpdateReserved(st, auth.NodeID, now) {
			return errRuntimeBusy
		}
		if _, err := s.taskRuntime.Store.NextIdleSequence(auth.NodeID); err != nil {
			return err
		}
		for id, old := range st.RuntimeUpdates {
			if old.NodeID != auth.NodeID {
				continue
			}
			if old.Sequence >= auth.Sequence {
				return errRuntimeBusy
			}
			if old.Status == runtimeupdate.Queued {
				old.Status, old.Package = runtimeupdate.Expired, nil
				st.RuntimeUpdates[id] = old
				s.auditRuntimeUpdate(st, old, "master", now)
			}
		}
		file, err := openRuntimeArchive(policy.ArchiveDir, entry)
		if err != nil {
			return err
		}
		sum := sha256.New()
		n, err := io.Copy(sum, io.LimitReader(file, entry.ArchiveLength+1))
		if err = errors.Join(err, file.Close()); err != nil || n != entry.ArchiveLength ||
			hex.EncodeToString(sum.Sum(nil)) != entry.ArchiveSHA256 {
			return errors.New("runtime archive does not match the signed digest")
		}
		st.RuntimeUpdates[entry.ID] = entry
		s.auditRuntimeUpdate(st, entry, ctx.Admin.ID, now)
		return nil
	})
	switch {
	case errors.Is(err, errRuntimeScope):
		http.NotFound(w, r)
	case errors.Is(err, errRuntimeBusy), errors.Is(err, taskdispatch.ErrConflict):
		http.Error(w, "runtime update expired, stale or node busy", http.StatusConflict)
	case err != nil:
		http.Error(w, "runtime update archive or queue unavailable", http.StatusServiceUnavailable)
	default:
		entry.Package = nil
		writeJSON(w, status, entry)
	}
}

func (s *Server) listRuntimeUpdates(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.adminAuth(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.TLS == nil || s.runtimeUpdates == nil {
		http.Error(w, "remote runtime update unavailable", http.StatusServiceUnavailable)
		return
	}
	nodeID := r.PathValue("node")
	entries := []store.RuntimeUpdate{}
	err := s.store.View(func(st store.State) error {
		node, ok := st.Nodes[nodeID]
		if !ok || !canManageNode(st.Admins[ctx.Admin.ID], node) {
			return errRuntimeScope
		}
		for _, entry := range st.RuntimeUpdates {
			if entry.NodeID == nodeID {
				entry.Package = nil
				entries = append(entries, entry)
			}
		}
		return nil
	})
	if errors.Is(err, errRuntimeScope) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "runtime update queue unavailable", http.StatusServiceUnavailable)
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Sequence > entries[j].Sequence })
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) runtimeSupervisor(r *http.Request) (string, bool) {
	node := r.PathValue("node")
	if r.TLS == nil || s.runtimeUpdates == nil || !security.ValidNodeID(node) {
		return "", false
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		return "", false
	}
	token, ok := strings.CutPrefix(headers[0], "Bearer ")
	if !ok || !security.ValidNodeSecret(token) {
		return "", false
	}
	digest := hash(token)
	if subtle.ConstantTimeCompare([]byte(digest), []byte(s.runtimeUpdates.NodeTokens[node])) != 1 {
		return "", false
	}
	err := s.store.View(func(st store.State) error {
		entry := st.Nodes[node]
		if !entry.Enrolled || entry.Disabled || entry.TokenHash == digest {
			return errRuntimeScope
		}
		return nil
	})
	return node, err == nil
}

func (s *Server) pollRuntimeUpdate(w http.ResponseWriter, r *http.Request) {
	node, ok := s.runtimeSupervisor(r)
	if !ok {
		http.Error(w, "runtime supervisor credential rejected", http.StatusUnauthorized)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	var entry store.RuntimeUpdate
	err = s.store.View(func(st store.State) error {
		for _, job := range st.RuntimeUpdates {
			if job.NodeID == node && (job.Status == runtimeupdate.Queued || job.Status == runtimeupdate.Delivered) {
				if entry.ID != "" {
					return errors.New("multiple runtime updates reserved for node")
				}
				entry = job
			}
		}
		return nil
	})
	if err == nil && entry.Status == runtimeupdate.Queued {
		err = s.store.Update(func(st *store.State) error {
			if !now.Before(entry.ExpiresAt) {
				entry.Status, entry.Package = runtimeupdate.Expired, nil
			} else {
				if entry.Package == nil {
					return errors.New("runtime proof missing")
				}
				if _, err := s.taskRuntime.Store.NextIdleSequence(node); err != nil {
					return err
				}
				entry.Status = runtimeupdate.Delivered
			}
			st.RuntimeUpdates[entry.ID] = entry
			s.auditRuntimeUpdate(st, entry, node, now)
			return nil
		})
	}
	switch {
	case err != nil:
		http.Error(w, "runtime update queue unavailable", http.StatusServiceUnavailable)
	case entry.Status != runtimeupdate.Delivered:
		w.WriteHeader(http.StatusNoContent)
	case entry.Package == nil:
		http.Error(w, "runtime proof missing", http.StatusServiceUnavailable)
	default:
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, runtimeupdate.Delivery{ID: entry.ID, Package: *entry.Package})
	}
}

func (s *Server) acceptRuntimeReceipt(w http.ResponseWriter, r *http.Request) {
	node, ok := s.runtimeSupervisor(r)
	if !ok {
		http.Error(w, "runtime supervisor credential rejected", http.StatusUnauthorized)
		return
	}
	var receipt runtimeupdate.Receipt
	if decodeRuntimeRequest(w, r, 4096, &receipt) != nil || !receipt.Valid() {
		http.Error(w, "invalid runtime receipt", http.StatusBadRequest)
		return
	}
	err := s.store.Update(func(st *store.State) error {
		entry, ok := st.RuntimeUpdates[receipt.ID]
		if !ok || entry.NodeID != node {
			return errRuntimeScope
		}
		if entry.Status == receipt.Status && entry.CurrentPair == receipt.CurrentPair {
			return nil
		}
		if entry.Status != runtimeupdate.Delivered ||
			receipt.Status == runtimeupdate.Committed && receipt.CurrentPair == entry.ExpectedPair ||
			receipt.Status == runtimeupdate.RolledBack && receipt.CurrentPair != entry.ExpectedPair {
			return errRuntimeBusy
		}
		entry.Status, entry.CurrentPair, entry.Package = receipt.Status, receipt.CurrentPair, nil
		st.RuntimeUpdates[entry.ID] = entry
		s.auditRuntimeUpdate(st, entry, node, time.Now())
		return nil
	})
	switch {
	case errors.Is(err, errRuntimeScope):
		http.NotFound(w, r)
	case errors.Is(err, errRuntimeBusy):
		http.Error(w, "runtime receipt conflicts with delivery", http.StatusConflict)
	case err != nil:
		http.Error(w, "runtime receipt unavailable", http.StatusServiceUnavailable)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// The checkpoint authorizes the read before streaming. The large ZIP is not
// buffered by the checkpoint and its bytes are independently checked on node.
func (s *Server) serveRuntimeArchive(w http.ResponseWriter, r *http.Request) {
	if s.runtimeUpdates == nil {
		http.NotFound(w, r)
		return
	}
	var entry store.RuntimeUpdate
	err := s.runWithTaskCheckpoint(r.Context(), func() error {
		node, ok := s.runtimeSupervisor(r)
		if !ok {
			return errRuntimeScope
		}
		now, err := s.taskRuntime.currentTime()
		if err != nil {
			return err
		}
		return s.store.View(func(st store.State) error {
			entry = st.RuntimeUpdates[r.PathValue("id")]
			if entry.NodeID != node || entry.Status != runtimeupdate.Delivered || !now.Before(entry.ExpiresAt) {
				return errRuntimeScope
			}
			return nil
		})
	})
	if errors.Is(err, errRuntimeScope) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "runtime archive unavailable", http.StatusServiceUnavailable)
		return
	}
	archive, err := openRuntimeArchive(s.runtimeUpdates.ArchiveDir, entry)
	if err != nil {
		http.Error(w, "runtime archive unavailable", http.StatusServiceUnavailable)
		return
	}
	defer archive.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.FormatInt(entry.ArchiveLength, 10))
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
	_, _ = io.CopyN(w, archive, entry.ArchiveLength)
}

func openRuntimeArchive(dir string, entry store.RuntimeUpdate) (*os.File, error) {
	if !runtimeupdate.ValidDigest(entry.ArchiveSHA256) {
		return nil, errors.New("invalid archive digest")
	}
	path := filepath.Join(dir, entry.ArchiveSHA256+".zip")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() != entry.ArchiveLength {
		return nil, errors.New("archive must be an approved regular file with the signed length")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != entry.ArchiveLength {
		file.Close()
		return nil, errors.New("runtime archive changed during open")
	}
	return file, nil
}

func (s *Server) auditRuntimeUpdate(st *store.State, entry store.RuntimeUpdate, actor string, now time.Time) {
	s.appendAudit(st, store.Audit{At: now.Unix(), Actor: actor, ResourceType: "node", Resource: entry.NodeID,
		NodeID: entry.NodeID, Action: "runtime.update", Detail: entry.ID, Outcome: entry.Status})
}
