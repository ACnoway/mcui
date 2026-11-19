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
)

type InstallExecutor interface {
	ExecuteInstall(context.Context, []byte, string) (json.RawMessage, error)
}

type InstallArtifacts interface {
	LookupCoreManifest(context.Context, string, string, int64) (artifacttrust.Target, error)
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
	if task.State != taskledger.Pending || now.Before(install.NotBefore) {
		return installAcknowledgments(task, lastVersion), nil
	}
	var artifactErr error
	if install.ActiveAt(now) {
		artifactErr = r.xrayInstall.prepare(ctx, install)
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

func (r *installRuntime) prepare(ctx context.Context, install lifecycleauth.InstallTask) error {
	if install.Architecture != runtime.GOARCH {
		return lifecycleauth.ErrDenied
	}
	target, err := r.artifacts.LookupCoreManifest(ctx, "xray", install.Version, install.ManifestVersion)
	if err != nil {
		return err
	}
	if target.SHA256 != install.SHA256 || target.Architecture != install.Architecture || target.SignatureStatus == "unverified" {
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
