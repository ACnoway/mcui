//go:build linux

package runtimeupdate

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/runtimehealth"
	"github.com/ACnoway/mcui/internal/security"
)

// Poll uses a root-only credential so the Agent cannot acknowledge a runtime
// transaction. The Master origin and credential are provisioned locally.
func (m *Manager) Poll(ctx context.Context, master, caPath, tokenPath string, clock func() (time.Time, error)) error {
	origin, err := security.MasterOrigin(master)
	if err != nil {
		return err
	}
	var ca []byte
	if caPath != "" {
		ca, err = readTrusted(caPath, 1<<20)
		if err != nil {
			return err
		}
	}
	file, size, err := openTrusted(tokenPath, 128)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
		file.Close()
		return errors.New("runtime supervisor token must be a private root file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, size+1))
	if err = errors.Join(err, file.Close()); err != nil || int64(len(raw)) != size {
		return errors.New("runtime supervisor token changed during read")
	}
	token := strings.TrimSpace(string(raw))
	if !security.ValidNodeSecret(token) {
		return errors.New("invalid runtime supervisor token")
	}
	client, err := security.NewMasterHTTPClient(ca, 2*time.Minute)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	return m.poll(ctx, client, origin, token, clock)
}

func (m *Manager) RepairPending(ctx context.Context) error {
	state, err := m.Status()
	if err != nil {
		return err
	}
	_, markerErr := os.Lstat(filepath.Join(m.dir, runtimehealth.TrialFile))
	if state.Pending != nil || markerErr == nil {
		return m.Repair(ctx)
	}
	if errors.Is(markerErr, os.ErrNotExist) {
		return nil
	}
	return markerErr
}

func (m *Manager) poll(ctx context.Context, client *http.Client, origin, token string, clock func() (time.Time, error)) error {
	if err := m.RepairPending(ctx); err != nil {
		return err
	}
	state, err := m.available()
	if err != nil {
		return err
	}
	base := origin + RemoteEndpoint + state.NodeID
	if state.RemoteReceipt != nil {
		if state.RemoteReceipt.Status != Rejected {
			if err := m.services.Healthy(ctx); err != nil {
				return err
			}
		}
		body, err := json.Marshal(state.RemoteReceipt)
		if err != nil {
			return err
		}
		res, err := remoteRequest(ctx, client, http.MethodPost, base+"/receipt", token, body)
		if err != nil {
			return err
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			return fmt.Errorf("Master rejected runtime receipt: HTTP %d", res.StatusCode)
		}
		state.RemoteReceipt = nil
		// Finish this timer invocation. A lost response or local write failure
		// resends the identical receipt on the next invocation.
		return m.save(state)
	}
	res, err := remoteRequest(ctx, client, http.MethodPost, base+"/poll", token, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("runtime poll failed: HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxPackageJSON+1))
	var delivery Delivery
	if err != nil || len(raw) > MaxPackageJSON || json.Unmarshal(raw, &delivery, json.RejectUnknownMembers(true)) != nil ||
		delivery.ID != delivery.Package.ID() {
		return errors.New("invalid runtime delivery")
	}
	now, err := clock()
	if err != nil {
		return err
	}
	auth, artifact, expiry, err := delivery.Package.Verify(state.ReleaseKey, state.AuthorizationKey)
	if err != nil {
		return err
	}
	if now.IsZero() || now.Before(auth.NotBefore) {
		return errors.New("trusted time has not reached runtime authorization start")
	}
	if !state.accepts(auth) || !auth.MatchesTime(now, expiry) {
		state.RemoteReceipt = &Receipt{ID: delivery.ID, Status: Rejected, CurrentPair: state.Current.Digest()}
		return m.save(state)
	}
	if err := m.services.Healthy(ctx); err != nil {
		return err
	}
	path := filepath.Join(m.dir, "remote.zip")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer os.Remove(path)
	res, err = remoteRequest(ctx, client, http.MethodGet, base+"/archive/"+delivery.ID, token, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength != artifact.Length {
		return fmt.Errorf("runtime archive unavailable or wrong length: HTTP %d", res.StatusCode)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := io.Copy(file, io.LimitReader(res.Body, artifact.Length+1))
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	if n != artifact.Length {
		return errors.New("incomplete runtime archive")
	}
	pair, err := m.stageArchiveFile(ctx, artifact, path)
	if err != nil {
		return err
	}
	if pair.Digest() == state.Current.Digest() {
		state.RemoteReceipt = &Receipt{ID: delivery.ID, Status: Rejected, CurrentPair: state.Current.Digest()}
		return m.save(state)
	}
	state.RemoteReceipt = &Receipt{ID: delivery.ID, Status: Delivered, CurrentPair: state.Current.Digest()}
	return m.activate(ctx, state, pair, auth, expiry, clock)
}

func remoteRequest(ctx context.Context, client *http.Client, method, endpoint, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}
