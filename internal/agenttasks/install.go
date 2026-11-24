package agenttasks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/taskledger"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

type InstallExecutor interface {
	ExecuteInstall(context.Context, []byte, string) (json.RawMessage, error)
}

type installReconciler interface {
	ReconcileInstall(context.Context, []byte) (json.RawMessage, error)
}

type InstallArtifacts interface {
	LookupOfficialRelease(context.Context, string, string, string, string) (artifacttrust.Target, error)
	Download(context.Context, artifacttrust.Target) (string, error)
}

type installRuntime struct {
	key       lifecycleauth.InstallKey
	artifacts InstallArtifacts
	executor  InstallExecutor
}

func (r *Runner) ConfigureXrayInstall(key lifecycleauth.InstallKey, artifacts InstallArtifacts, executor InstallExecutor) error {
	if key.ID == "" || len(key.PublicKey) != 32 || artifacts == nil || executor == nil || r.trustedNow == nil || r.xrayInstall != nil || runtime.GOOS != "linux" {
		return errors.New("invalid Xray install runtime")
	}
	for id, status := range r.processor.keys {
		if id == key.ID || bytes.Equal(status.PublicKey, key.PublicKey) {
			return errors.New("Xray installs require a separate signing key")
		}
	}
	key.PublicKey = bytes.Clone(key.PublicKey)
	r.xrayInstall = &installRuntime{key, artifacts, executor}
	return nil
}

func (r *Runner) ProcessXrayInstall(ctx context.Context, raw []byte, leaseID string, skip []byte, lastVersion int64, serverTime time.Time) ([]Ack, error) {
	if r.xrayInstall == nil || len(leaseID) != 32 || lastVersion < 0 {
		return nil, errors.New("Xray install runtime unavailable")
	}
	now, err := r.deliveryTime(serverTime)
	if err != nil {
		return nil, err
	}
	raw = bytes.Clone(raw)
	install, err := r.xrayInstall.key.Verify(raw)
	if err != nil || install.NodeID != r.processor.node {
		return nil, lifecycleauth.ErrDenied
	}
	task, err := r.ledger.AcceptValidated(taskledger.Task{
		ID: install.TaskID, Sequence: install.Sequence, Envelope: raw, NotBefore: install.NotBefore, ExpiresAt: install.ExpiresAt,
	}, func() (time.Time, error) {
		current, err := r.trustedNow()
		if err != nil || current.Before(now) {
			return time.Time{}, ErrTrustedTime
		}
		return current, nil
	})
	if err != nil {
		return nil, err
	}
	if len(skip) != 0 {
		task, err = r.processor.ApplySkip(ctx, skip, now, task.ID, task.Sequence)
		if err != nil {
			return nil, err
		}
		return installAcknowledgments(task, lastVersion), nil
	}
	if task.State == taskledger.Reconciliation {
		task, err = r.reconcileXrayInstall(ctx, task, install)
		if err != nil {
			return nil, err
		}
	}
	if task.State != taskledger.Pending || now.Before(install.NotBefore) {
		return installAcknowledgments(task, lastVersion), nil
	}
	var artifactErr error
	if install.ActiveAt(now) {
		artifactErr = r.xrayInstall.prepare(artifacttrust.WithInstallLease(ctx, raw, leaseID), install)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := r.trustedNow()
	if err != nil || current.Before(now) {
		return nil, ErrTrustedTime
	}
	task, err = r.ledger.Start(task.Sequence, current)
	if err != nil {
		return nil, err
	}
	if task.State == taskledger.Running {
		state := taskledger.Failed
		result, _ := json.Marshal(lifecycleauth.InstallResult{Outcome: "FAILED", Version: install.Version, SHA256: install.SHA256})
		if artifactErr == nil {
			rawResult, executeErr := r.xrayInstall.executor.ExecuteInstall(ctx, task.Envelope, leaseID)
			var outcome lifecycleauth.InstallResult
			if executeErr != nil || json.Unmarshal(rawResult, &outcome) != nil || outcome.Version != install.Version || outcome.SHA256 != install.SHA256 ||
				(outcome.Outcome != "SUCCEEDED" && outcome.Outcome != "FAILED" && outcome.Outcome != "ROLLED_BACK") {
				if err := r.ledger.RequireReconciliation(task.Sequence, []byte(`{"error_code":"reconciliation_required"}`)); err != nil {
					return nil, err
				}
				task, err = r.ledger.Get(task.Sequence)
				return installAcknowledgments(task, lastVersion), err
			}
			result, _ = json.Marshal(outcome)
			if outcome.Outcome == "SUCCEEDED" {
				state = taskledger.Succeeded
			}
		}
		if err := r.ledger.Finish(task.Sequence, state, result); err != nil {
			return nil, err
		}
		task, err = r.ledger.Get(task.Sequence)
		if err != nil {
			return nil, err
		}
	}
	return installAcknowledgments(task, lastVersion), nil
}

// ReconcileXrayInstall handles a Master delivery for a fenced sequence. It
// requires an existing exact local envelope and has no path to start a task.
func (r *Runner) ReconcileXrayInstall(ctx context.Context, raw []byte, lastVersion int64) ([]Ack, error) {
	if r.xrayInstall == nil || lastVersion < 1 {
		return nil, lifecycleauth.ErrDenied
	}
	install, err := r.xrayInstall.key.Verify(raw)
	if err != nil || install.NodeID != r.processor.node {
		return nil, lifecycleauth.ErrDenied
	}
	task, err := r.ledger.Get(install.Sequence)
	if err != nil || task.ID != install.TaskID || !bytes.Equal(task.Envelope, raw) {
		return nil, lifecycleauth.ErrDenied
	}
	if task.State == taskledger.Reconciliation {
		task, err = r.reconcileXrayInstall(ctx, task, install)
		if err != nil {
			return nil, err
		}
	}
	var result lifecycleauth.InstallResult
	if (task.State != taskledger.Succeeded && task.State != taskledger.Failed) ||
		json.Unmarshal(task.Result, &result) != nil || result.Version != install.Version || result.SHA256 != install.SHA256 ||
		(task.State == taskledger.Succeeded && result.Outcome != "SUCCEEDED") ||
		(task.State == taskledger.Failed && result.Outcome != "ROLLED_BACK") {
		return nil, nil
	}
	return []Ack{{StatusVersion: lastVersion + 1, Status: result.Outcome, Result: task.Result}}, nil
}

func (r *Runner) reconcileXrayInstall(ctx context.Context, task taskledger.Task, install lifecycleauth.InstallTask) (taskledger.Task, error) {
	reconciler, ok := r.xrayInstall.executor.(installReconciler)
	if !ok {
		return task, nil
	}
	raw, err := reconciler.ReconcileInstall(ctx, task.Envelope)
	var result lifecycleauth.InstallResult
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Version != install.Version || result.SHA256 != install.SHA256 {
		return task, nil
	}
	var state taskledger.State
	switch result.Outcome {
	case "SUCCEEDED":
		state = taskledger.Succeeded
	case "ROLLED_BACK":
		state = taskledger.Failed
	default:
		return task, nil
	}
	canonical, err := json.Marshal(result)
	if err != nil {
		return task, err
	}
	if err := r.ledger.FinishReconciled(task.Sequence, state, canonical); err != nil {
		return task, err
	}
	task.State, task.Result = state, canonical
	return task, nil
}

func (r *installRuntime) prepare(ctx context.Context, install lifecycleauth.InstallTask) error {
	if install.Architecture != runtime.GOARCH {
		return lifecycleauth.ErrDenied
	}
	if lifecycleauth.IsControlOperation(install.Operation) {
		return nil
	}
	if install.ManifestVersion != 0 || install.SignedManifest {
		return lifecycleauth.ErrDenied
	}
	if install.Operation == xrayconfig.Operation {
		return nil
	}
	target, err := r.artifacts.LookupOfficialRelease(ctx, "xray", install.Version, install.Architecture, install.SHA256)
	if err != nil {
		return err
	}
	if target.SHA256 != install.SHA256 || target.Architecture != install.Architecture {
		return lifecycleauth.ErrDenied
	}
	_, err = r.artifacts.Download(ctx, target)
	return err
}

func installAcknowledgments(task taskledger.Task, lastVersion int64) []Ack {
	acks := acknowledgments(task, lastVersion)
	if task.State == taskledger.Failed {
		var result lifecycleauth.InstallResult
		if json.Unmarshal(task.Result, &result) == nil && result.Outcome == "ROLLED_BACK" {
			acks[len(acks)-1].Status = "ROLLED_BACK"
		}
	}
	return acks
}
