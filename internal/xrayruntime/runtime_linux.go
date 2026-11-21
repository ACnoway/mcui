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
	"strconv"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/corecatalog"
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
)

type Release struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type selection struct {
	Release Release `json:"release"`
	Running bool    `json:"running"`
}

type intent struct {
	Action      Action    `json:"action"`
	Next        selection `json:"next"`
	InstallHash string    `json:"install_hash,omitempty"`
	ControlHash string    `json:"control_hash,omitempty"`
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
}

type service interface {
	preflight(context.Context) error
	start(context.Context) error
	stop(context.Context) error
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
	return r.apply(ctx, action, release, trust, 0, "", nil)
}

// ApplyWithManifest pins the approved manifest version across lookup,
// download, preflight and activation.
func (r *Runtime) ApplyWithManifest(ctx context.Context, action Action, release Release, trust *artifacttrust.Client, manifestVersion int64) error {
	if manifestVersion <= 0 {
		return artifacttrust.ErrUntrustedTarget
	}
	return r.apply(ctx, action, release, trust, manifestVersion, "", nil)
}

// InstallAuthorized rechecks the remote authorization before candidate
// execution and immediately before recording any activation intent.
func (r *Runtime) InstallAuthorized(ctx context.Context, release Release, trust *artifacttrust.Client, manifestVersion int64, hash string, authorize func(context.Context) error) (string, error) {
	if manifestVersion <= 0 || !validTaskHash(hash) || authorize == nil {
		return "FAILED", nil
	}
	return taskOutcome(r.apply(ctx, Install, release, trust, manifestVersion, hash, authorize))
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

func (r *Runtime) apply(ctx context.Context, action Action, release Release, trust *artifacttrust.Client, manifestVersion int64, hash string, authorize func(context.Context) error) error {
	state, err := r.ready()
	if err != nil {
		return errors.Join(errUnknown, err)
	}
	next := selection{Release: release, Running: action == Install || state.Current.Running}
	if err := validateTransition(state.Current, intent{Action: action, Next: next}); err != nil {
		return err
	}
	if action != Install && action != Upgrade && action != Downgrade {
		return errors.New("invalid Xray artifact action")
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
	if !isServiceControl(action) || !validTaskHash(hash) || authorize == nil {
		return "FAILED", nil
	}
	return taskOutcome(r.control(ctx, action, expected, hash, authorize))
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

// ReconcileInstall returns the persisted result of the exact signed install.
func (r *Runtime) ReconcileInstall(ctx context.Context, release Release, hash string) (string, error) {
	return r.reconcileTask(ctx, Install, release, hash)
}

// ReconcileControl only reads a receipt or rolls back a matching transaction.
func (r *Runtime) ReconcileControl(ctx context.Context, action Action, release Release, hash string) (string, error) {
	if !isServiceControl(action) {
		return "", errUnknown
	}
	return r.reconcileTask(ctx, action, release, hash)
}

func (r *Runtime) reconcileTask(ctx context.Context, action Action, release Release, hash string) (string, error) {
	if !release.valid() || !validTaskHash(hash) {
		return "", errUnknown
	}
	state, err := r.readStatus()
	if err != nil {
		return "", err
	}
	if state.Pending != nil {
		pending := state.Pending
		pendingHash := pending.InstallHash
		if action != Install {
			pendingHash = pending.ControlHash
		}
		if pending.Action != action || pendingHash != hash || pending.Next.Release != release {
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
	if action != Install {
		receipt = state.ControlReceipt
		if receipt != nil && receipt.Action != action {
			return "", errUnknown
		}
	}
	if receipt == nil || receipt.Hash != hash || receipt.Release != release {
		return "", errUnknown
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

func isServiceControl(action Action) bool {
	return action == Start || action == Stop
}

func (s *Status) recordReceipt(attempt intent, outcome string) {
	if attempt.InstallHash != "" {
		s.InstallReceipt = &taskReceipt{Hash: attempt.InstallHash, Release: attempt.Next.Release, Outcome: outcome}
	} else if attempt.ControlHash != "" {
		s.ControlReceipt = &taskReceipt{Hash: attempt.ControlHash, Release: attempt.Next.Release, Outcome: outcome, Action: attempt.Action}
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
	state.Current, state.Pending = next, nil
	state.LastAction, state.LastResult = action, "committed"
	state.recordReceipt(attempt, "SUCCEEDED")
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
	if current.Release != next.Release && next.Release != (Release{}) && !next.Running {
		// A paused installation still needs a startup check before replacing
		// the committed bundle. Leave it stopped after the bounded check.
		if err := r.reconcile(ctx, selection{Release: next.Release, Running: true}); err != nil {
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
		return r.service.start(ctx)
	}
	return r.service.stop(ctx)
}

func (r *Runtime) runPreflight(ctx context.Context, release Release) (err error) {
	if err := r.point("candidate", release); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, r.clearCandidate()) }()
	return r.service.preflight(ctx)
}

func (r *Runtime) clearCandidate() error { return r.point("candidate", Release{}) }

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

func compareVersions(left, right string) int {
	first, second := strings.Split(left[1:], "."), strings.Split(right[1:], ".")
	for i := range first {
		a, _ := strconv.Atoi(first[i])
		b, _ := strconv.Atoi(second[i])
		if a != b {
			return a - b
		}
	}
	return 0
}

func validateTransition(current selection, pending intent) error {
	next := pending.Next
	if (next.Release != (Release{}) && !next.Release.valid()) || (next.Release == (Release{}) && next.Running) {
		return errors.New("invalid target Xray selection")
	}
	valid := false
	switch pending.Action {
	case Install:
		valid = current == (selection{}) && next.Release.valid() && next.Running
	case Upgrade, Downgrade:
		if current.Release.valid() && next.Release.valid() && current.Running == next.Running {
			order := compareVersions(next.Release.Version, current.Release.Version)
			valid = (pending.Action == Upgrade && order > 0) || (pending.Action == Downgrade && order < 0)
		}
	case Start, Stop:
		valid = current.Release.valid() && current.Release == next.Release && next.Running == (pending.Action == Start)
	case Uninstall:
		valid = current.Release.valid() && next == (selection{})
	}
	if !valid {
		return fmt.Errorf("Xray %s conflicts with the committed release", pending.Action)
	}
	return nil
}
