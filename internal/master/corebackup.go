package master

import (
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
)

func (s *Server) serveXrayBackup(w http.ResponseWriter, r *http.Request) {
	if !secureRequest(r) {
		http.Error(w, "TLS required", http.StatusUpgradeRequired)
		return
	}
	if !s.allowAttempt("helper-artifact:" + clientAddress(r)) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var in artifacttrust.BackupRequest
	if readJSON(r, &in) != nil || len(in.LeaseID) != 32 || len(in.Task) == 0 || in.Length < 1 || in.Length > 512<<20 {
		http.Error(w, "invalid artifact request", http.StatusBadRequest)
		return
	}
	var file *os.File
	var status int
	err := s.runWithTaskState(r.Context(), func() error {
		file, status = s.openXrayBackup(in)
		return nil
	})
	if file != nil {
		defer file.Close()
	}
	if err != nil {
		http.Error(w, "Master task checkpoint unavailable", http.StatusServiceUnavailable)
		return
	}
	if file == nil {
		http.Error(w, "requested backup artifact unavailable", status)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(in.Length, 10))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.CopyN(w, file, in.Length)
}

func (s *Server) openXrayBackup(in artifacttrust.BackupRequest) (*os.File, int) {
	s.nodeAccess.RLock()
	defer s.nodeAccess.RUnlock()
	cache, ok := s.coreBackups.(interface {
		OpenExact(string, string, string, string, int64) (*os.File, error)
	})
	if !ok || s.taskRuntime == nil || s.taskRuntime.XrayInstallPolicy == nil {
		return nil, http.StatusServiceUnavailable
	}
	task, err := s.verifyStoredXrayTask(in.Task, true)
	if err != nil || (task.Operation != "core.install" && !lifecycleauth.IsVersionChange(task.Operation)) {
		return nil, http.StatusForbidden
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		return nil, http.StatusServiceUnavailable
	}
	if _, err := s.taskRuntime.Store.ValidateInstallLease(task, in.LeaseID, in.Task, now); err != nil {
		return nil, http.StatusForbidden
	}
	file, err := cache.OpenExact("xray", task.Version, task.Architecture, task.SHA256, in.Length)
	if err != nil {
		return nil, http.StatusNotFound
	}
	return file, http.StatusOK
}
