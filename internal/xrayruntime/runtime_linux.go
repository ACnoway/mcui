//go:build linux

// Package xrayruntime implements the local, privileged Xray lifecycle.
package xrayruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const StateDir = "/var/lib/mcui-xray"

var errRollback = errors.New("Xray installation rolled back")
var errUnknown = errors.New("Xray transaction requires reconciliation")
var errCommitted = errors.New("Xray transaction committed")

type Action string

const (
	Install   Action = "install"
	Upgrade   Action = "upgrade"
	Downgrade Action = "downgrade"
	Start     Action = "start"
	Stop      Action = "stop"
	Uninstall Action = "uninstall"
	Configure Action = "apply_config"
)

type Release struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type selection struct {
	Release  Release              `json:"release"`
	Running  bool                 `json:"running"`
	Config   xrayconfig.Reference `json:"config,omitzero"`
	Revision int64                `json:"revision,omitempty"`
}

type intent struct {
	Action      Action    `json:"action"`
	Next        selection `json:"next"`
	InstallHash string    `json:"install_hash,omitempty"`
	ControlHash string    `json:"control_hash,omitempty"`
	ConfigHash  string    `json:"config_hash,omitempty"`
}

type taskReceipt struct {
	Hash    string  `json:"hash"`
	Release Release `json:"release"`
	Outcome string  `json:"outcome"`
	Action  Action  `json:"action,omitempty"`
}

type Status struct {
	Schema         int          `json:"schema"`
	Current        selection    `json:"current"`
	Previous       Release      `json:"previous"`
	Pending        *intent      `json:"pending,omitempty"`
	LastAction     Action       `json:"last_action,omitempty"`
	LastResult     string       `json:"last_result,omitempty"`
	InstallReceipt *taskReceipt `json:"install_receipt,omitempty"`
	ControlReceipt *taskReceipt `json:"control_receipt,omitempty"`
	ConfigReceipt  *taskReceipt `json:"config_receipt,omitempty"`
	ConfigRevision int64        `json:"config_revision,omitempty"`
}

type service interface {
	preflight(context.Context) error
	start(context.Context) error
	stop(context.Context) error
}

type releaseTrust interface {
	Lookup(context.Context, string, string) (artifacttrust.Target, error)
	LookupCoreManifest(context.Context, string, string, int64) (artifacttrust.Target, error)
	Download(context.Context, artifacttrust.Target) (string, error)
	Revalidate(context.Context, artifacttrust.Target) error
}

// Runtime holds the exclusive local lifecycle lock until Close.
type Runtime struct {
	dir     string
	lock    *os.File
	service service
}

func Open(initialize bool) (*Runtime, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the Xray runtime requires local root")
	}
	return openRuntime(StateDir, systemdService{}, initialize)
}

func (r *Runtime) Close() error { return r.lock.Close() }

func (r *Runtime) Status() (Status, error) { return r.readStatus() }

// Apply fetches only the exact operator-selected and authorized release.
func (r *Runtime) Apply(ctx context.Context, action Action, release Release, trust *artifacttrust.Client) error {
	return r.apply(ctx, action, Release{}, release, trust, 0, "", nil)
}

// ApplyWithManifest pins the approved manifest version across lookup,
// download, preflight and activation.
func (r *Runtime) ApplyWithManifest(ctx context.Context, action Action, release Release, trust *artifacttrust.Client, manifestVersion int64) error {
	if manifestVersion <= 0 {
		return artifacttrust.ErrUntrustedTarget
	}
	return r.apply(ctx, action, Release{}, release, trust, manifestVersion, "", nil)
}

// ApplyAuthorized rechecks the remote authorization before candidate
// execution and immediately before recording any activation intent.
func (r *Runtime) ApplyAuthorized(ctx context.Context, action Action, expected, release Release, trust releaseTrust, manifestVersion int64, hash string, authorize func(context.Context) error) (string, error) {
	safeSource := (action == Install && expected == (Release{})) || ((action == Upgrade || action == Downgrade) && expected.valid())
	if !safeSource || manifestVersion <= 0 || !validTaskHash(hash) || authorize == nil {
		return "FAILED", nil
	}
	return taskOutcome(r.apply(ctx, action, expected, release, trust, manifestVersion, hash, authorize))
}

func taskOutcome(err error) (string, error) {
	switch {
	case err == nil || errors.Is(err, errCommitted):
		return "SUCCEEDED", nil
	case errors.Is(err, errRollback):
		return "ROLLED_BACK", nil
	case errors.Is(err, errUnknown):
		return "", err
	default:
		return "FAILED", nil
	}
}

func (r *Runtime) apply(ctx context.Context, action Action, expected, release Release, trust releaseTrust, manifestVersion int64, hash string, authorize func(context.Context) error) error {
	state, err := r.ready()
	if err != nil {
		return errors.Join(errUnknown, err)
	}
	if expected != (Release{}) && state.Current.Release != expected {
		return errors.New("current Xray release does not match the expected release")
	}
	next := selection{Release: release, Running: action == Install || state.Current.Running}
	if err := validateTransition(state.Current, intent{Action: action, Next: next}); err != nil {
		return err
	}
	if !isArtifactAction(action) {
		return errors.New("invalid Xray artifact action")
	}
	if trust == nil {
		return artifacttrust.ErrUntrustedTarget
	}
	var target artifacttrust.Target
	if manifestVersion != 0 {
		target, err = trust.LookupCoreManifest(ctx, "xray", release.Version, manifestVersion)
	} else {
		target, err = trust.Lookup(ctx, "xray", release.Version)
	}
	if err != nil {
		return err
	}
	if target.SHA256 != release.SHA256 || target.ArchiveFormat != "zip" || target.SignatureStatus == "unverified" {
		return errors.New("Xray artifact does not match the reviewed release")
	}
	if err := r.stage(ctx, release, target.Size, func() (string, error) {
		return trust.Download(ctx, target)
	}); err != nil {
		return fmt.Errorf("stage Xray release: %w", err)
	}
	if authorize != nil {
		if err := authorize(ctx); err != nil {
			return err
		}
	}
	if err := r.runPreflight(ctx, release); err != nil {
		return fmt.Errorf("preflight Xray release: %w", err)
	}
	if err := trust.Revalidate(ctx, target); err != nil {
		return err
	}
	if authorize != nil {
		if err := authorize(ctx); err != nil {
			return err
		}
	}
	return r.change(ctx, state, intent{Action: action, Next: next, InstallHash: hash})
}

func (r *Runtime) Control(ctx context.Context, action Action, expected Release) error {
	return r.control(ctx, action, expected, "", nil)
}

// ControlAuthorized limits remote control to the fixed service and confirms the
// current lease before committing an intent for the exact installed release.
func (r *Runtime) ControlAuthorized(ctx context.Context, action Action, expected Release, hash string, authorize func(context.Context) error) (string, error) {
	if !isControlAction(action) || !validTaskHash(hash) || authorize == nil {
		return "FAILED", nil
	}
	err := r.control(ctx, action, expected, hash, authorize)
	if action == Uninstall && errors.Is(err, errCommitted) {
		return "", err // Committed removal still needs to finish pruning the old bundles.
	}
	return taskOutcome(err)
}

func (r *Runtime) control(ctx context.Context, action Action, expected Release, hash string, authorize func(context.Context) error) error {
	state, err := r.ready()
	if err != nil {
		if authorize != nil {
			return errors.Join(errUnknown, err)
		}
		return err
	}
	if !expected.valid() || state.Current.Release != expected {
		return errors.New("current Xray release does not match the expected release")
	}
	next := state.Current
	switch action {
	case Start:
		next.Running = true
	case Stop:
		next.Running = false
	case Uninstall:
		next = selection{}
	default:
		return errors.New("invalid Xray control action")
	}
	if authorize != nil {
		if err := authorize(ctx); err != nil {
			return err
		}
	}
	return r.change(ctx, state, intent{Action: action, Next: next, ControlHash: hash})
}

// ReconcileTask reads a receipt or rolls back the exact interrupted transaction.
func (r *Runtime) ReconcileTask(ctx context.Context, action Action, release Release, hash string) (string, error) {
	if (!isArtifactAction(action) && !isControlAction(action) && action != Configure) || !release.valid() || !validTaskHash(hash) {
		return "", errUnknown
	}
	state, err := r.readStatus()
	if err != nil {
		return "", err
	}
	if state.Pending != nil {
		pending := state.Pending
		pendingHash := pending.InstallHash
		if isControlAction(action) {
			pendingHash = pending.ControlHash
		} else if action == Configure {
			pendingHash = pending.ConfigHash
		}
		if pending.Action != action || pendingHash != hash || pending.receiptRelease(state.Current.Release) != release {
			return "", errUnknown
		}
		if err := r.rollback(ctx, state); err != nil {
			return "", err
		}
		state, err = r.readStatus()
		if err != nil {
			return "", err
		}
	}
	receipt := state.InstallReceipt
	if isControlAction(action) {
		receipt = state.ControlReceipt
	} else if action == Configure {
		receipt = state.ConfigReceipt
	}
	if receipt == nil || receipt.Hash != hash || receipt.Release != release {
		return "", errUnknown
	}
	if receipt.Action != action && !(action == Install && receipt.Action == "") {
		return "", errUnknown
	}
	if action == Uninstall && receipt.Outcome == "SUCCEEDED" {
		if err := r.prune(state); err != nil {
			return "", err
		}
	}
	if err := syncDir(filepath.Join(r.dir, "control")); err != nil {
		return "", err
	}
	return receipt.Outcome, nil
}

func validTaskHash(hash string) bool {
	if len(hash) != 64 || hash != strings.ToLower(hash) {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func isControlAction(action Action) bool {
	return action == Start || action == Stop || action == Uninstall
}

func isArtifactAction(action Action) bool {
	return action == Install || action == Upgrade || action == Downgrade
}

func (attempt intent) receiptRelease(current Release) Release {
	if attempt.Action == Uninstall {
		return current
	}
	return attempt.Next.Release
}

func (s *Status) recordReceipt(attempt intent, outcome string) {
	release := attempt.receiptRelease(s.Current.Release)
	if attempt.InstallHash != "" {
		s.InstallReceipt = &taskReceipt{Hash: attempt.InstallHash, Release: release, Outcome: outcome}
		if attempt.Action != Install {
			s.InstallReceipt.Action = attempt.Action
		}
	} else if attempt.ControlHash != "" {
		s.ControlReceipt = &taskReceipt{Hash: attempt.ControlHash, Release: release, Outcome: outcome, Action: attempt.Action}
	} else if attempt.ConfigHash != "" {
		s.ConfigReceipt = &taskReceipt{Hash: attempt.ConfigHash, Release: release, Outcome: outcome, Action: Configure}
	}
}

// Recover is also called on boot. A pending transaction always rolls back to
// the still-committed release before any later lifecycle operation may run.
func (r *Runtime) Recover(ctx context.Context) error {
	state, err := r.readStatus()
	if err != nil {
		return err
	}
	if state.Pending != nil {
		return r.rollback(ctx, state)
	}
	if err := r.clearCandidate(); err != nil {
		return err
	}
	if err := r.reconcile(ctx, state.Current); err != nil {
		return err
	}
	return r.prune(state)
}

func (r *Runtime) ready() (Status, error) {
	state, err := r.readStatus()
	if err != nil {
		return Status{}, err
	}
	if state.Pending != nil {
		return Status{}, errors.New("Xray transaction pending; run recover")
	}
	if err := r.clearCandidate(); err != nil {
		return Status{}, err
	}
	if err := r.prune(state); err != nil {
		return Status{}, err
	}
	return state, nil
}

func (r *Runtime) change(ctx context.Context, state Status, attempt intent) error {
	if err := validateTransition(state.Current, attempt); err != nil {
		return err
	}
	action, next := attempt.Action, attempt.Next
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.verifyBundle(state.Current.Release); err != nil {
		return errors.Join(errUnknown, fmt.Errorf("verify committed Xray bundle: %w", err))
	}
	state.Pending = &attempt
	if action == Configure {
		state.ConfigRevision = next.Revision
	}
	if err := r.save(state); err != nil {
		return errors.Join(errUnknown, fmt.Errorf("persist Xray transaction intent: %w", err))
	}
	if err := r.applySelection(ctx, state.Current, next); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if rollbackErr := r.rollback(rollbackCtx, state); rollbackErr != nil {
			return errors.Join(errUnknown, fmt.Errorf("apply Xray transaction: %w", err), rollbackErr)
		}
		return errors.Join(errRollback, fmt.Errorf("apply Xray transaction: %w", err))
	}
	if next.Release != state.Current.Release {
		state.Previous = state.Current.Release
	}
	if action == Uninstall {
		state.Previous = Release{}
	}
	state.recordReceipt(attempt, "SUCCEEDED")
	state.Current, state.Pending = next, nil
	state.LastAction, state.LastResult = action, "committed"
	if err := r.save(state); err != nil {
		// A rename may already have completed even when directory fsync fails.
		return errors.Join(errUnknown, fmt.Errorf("persist Xray commit; run recover before continuing: %w", err))
	}
	if err := r.prune(state); err != nil {
		return errors.Join(errCommitted, fmt.Errorf("bundle cleanup failed: %w", err))
	}
	return nil
}

func (r *Runtime) applySelection(ctx context.Context, current, next selection) error {
	if current.Config != next.Config {
		if err := r.service.stop(ctx); err != nil {
			return err
		}
	}
	if (current.Release != next.Release || current.Config != next.Config) && next.Release != (Release{}) && !next.Running {
		// A paused installation still needs a startup check before replacing
		// the committed bundle. Leave it stopped after the bounded check.
		check := next
		check.Running = true
		if err := r.reconcile(ctx, check); err != nil {
			return err
		}
	}
	return r.reconcile(ctx, next)
}

func (r *Runtime) rollback(ctx context.Context, state Status) error {
	if err := r.clearCandidate(); err != nil {
		return fmt.Errorf("ROLLBACK_FAILED: %w", err)
	}
	if err := r.service.stop(ctx); err != nil {
		return fmt.Errorf("ROLLBACK_FAILED: stop Xray: %w", err)
	}
	if err := r.reconcile(ctx, state.Current); err != nil {
		return fmt.Errorf("ROLLBACK_FAILED: restore committed Xray selection: %w", err)
	}
	state.LastAction, state.LastResult = state.Pending.Action, "rolled_back"
	state.recordReceipt(*state.Pending, "ROLLED_BACK")
	state.Pending = nil
	if err := r.save(state); err != nil {
		return fmt.Errorf("ROLLBACK_FAILED: persist Xray recovery: %w", err)
	}
	return r.prune(state)
}

func (r *Runtime) reconcile(ctx context.Context, next selection) error {
	if err := r.verifyBundle(next.Release); err != nil {
		return err
	}
	current, err := r.readPointer("current")
	if err != nil {
		return err
	}
	if current != next.Release.link() {
		if err := r.service.stop(ctx); err != nil {
			return err
		}
		if err := r.point("current", next.Release); err != nil {
			return err
		}
	}
	if next.Running {
		published, err := r.prepareRuntimeConfig(ctx, next)
		if err != nil {
			return err
		}
		if err := r.service.start(ctx); err != nil {
			return err
		}
		if len(published) != 0 {
			return r.service.(panelNetworkService).startPanelIngress(ctx, published)
		}
		return nil
	}
	if err := r.service.stop(ctx); err != nil {
		return err
	}
	_, err = r.prepareRuntimeConfig(ctx, next)
	return err
}

func (r *Runtime) runPreflight(ctx context.Context, release Release) error {
	return r.preflightConfig(ctx, release, []byte(bootstrapConfig))
}

func (r *Runtime) preflightConfig(ctx context.Context, release Release, data []byte) (err error) {
	if err := r.writeControl("candidate-config.json", data); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.clearCandidate()) }()
	if err := r.point("candidate", release); err != nil {
		return err
	}
	return r.service.preflight(ctx)
}

func (r *Runtime) clearCandidate() error {
	return errors.Join(r.point("candidate", Release{}), r.removeControl("candidate-config.json"))
}

func (r Release) valid() bool {
	return corecatalog.ValidXrayRelease(r.Version, r.SHA256)
}

func (r Release) key() string { return r.Version + "-" + r.SHA256 }

func (r Release) link() string {
	if r == (Release{}) {
		return ""
	}
	return filepath.Join("versions", r.key())
}

func validateTransition(current selection, pending intent) error {
	next := pending.Next
	if !next.validConfig() || (next.Release != (Release{}) && !next.Release.valid()) || (next.Release == (Release{}) && next.Running) {
		return errors.New("invalid target Xray selection")
	}
	valid := false
	switch pending.Action {
	case Install:
		valid = current == (selection{}) && next.Release.valid() && next.Running && next.Revision == 0
	case Upgrade, Downgrade:
		if current.Release.valid() && next.Release.valid() && current.Running == next.Running && next.Revision == 0 {
			order := corecatalog.CompareXrayVersions(next.Release.Version, current.Release.Version)
			valid = (pending.Action == Upgrade && order > 0) || (pending.Action == Downgrade && order < 0)
		}
	case Start, Stop:
		expected := current
		expected.Running = pending.Action == Start
		valid = current.Release.valid() && next == expected
	case Uninstall:
		valid = current.Release.valid() && next == (selection{})
	case Configure:
		valid = current.Release.valid() && current.Release == next.Release && current.Running == next.Running &&
			next.Revision > current.Revision && validTaskHash(pending.ConfigHash)
	}
	if !valid {
		return fmt.Errorf("Xray %s conflicts with the committed release", pending.Action)
	}
	return nil
}
