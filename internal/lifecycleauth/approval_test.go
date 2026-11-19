package lifecycleauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/protocol"
)

type testAuthority struct {
	policyDoc  policyDocument
	policy     *Policy
	requestKey ed25519.PrivateKey
	approveKey ed25519.PrivateKey
	taskKey    ed25519.PrivateKey
	now        time.Time
	proposal   Proposal
}

func newTestAuthority(t *testing.T) testAuthority {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	public := make([]string, len(keys))
	for i := range keys {
		pub, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], public[i] = private, base64.StdEncoding.EncodeToString(pub)
	}
	doc := policyDocument{SchemaVersion: 1, SigningKeyID: "xray-install-test", SigningPublicKey: public[2],
		Principals: []Principal{
			{ID: "operator-1", Role: "operator", PublicKey: public[0], NodeIDs: []string{"test-node"}},
			{ID: "security-1", Role: "security_admin", PublicKey: public[1], NodeIDs: []string{"test-node"}},
		},
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	p := Proposal{
		SchemaVersion: 1, Operation: "core.install", Core: "xray", TaskID: "test-install-task-000001",
		NodeID: "test-node", Sequence: 9, Version: "v26.10.31", Architecture: "amd64",
		SHA256: strings.Repeat("3a", 32), ManifestVersion: 7, RequesterID: "operator-1",
		ApproverID: "security-1", SigningKeyID: doc.SigningKeyID, CreatedAt: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(25 * time.Minute).Unix(),
	}
	return testAuthority{policyDoc: doc, policy: parseTestPolicy(t, doc), requestKey: keys[0],
		approveKey: keys[1], taskKey: keys[2], now: now, proposal: p}
}

func parseTestPolicy(t *testing.T, doc policyDocument) *Policy {
	t.Helper()
	policy, err := ParsePolicy(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (a testAuthority) approve(t *testing.T, p Proposal) Approval {
	t.Helper()
	request, err := a.policy.SignRequest(p, a.requestKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := a.policy.Approve(request, a.approveKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, approval)
	approval, err = ParseApproval(raw)
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func newLedger(t *testing.T) (string, *Ledger) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signer.db")
	if err := InitLedger(path); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	return path, ledger
}

func TestIssueExactInstallAndReplayAfterReopen(t *testing.T) {
	a := newTestAuthority(t)
	path, ledger := newLedger(t)
	approval := a.approve(t, a.proposal)
	raw, err := a.policy.Issue(t.Context(), ledger, approval, a.taskKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Verify(protocol.Task, raw, a.taskKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	id, err := a.policy.VerifyApproval(approval, a.now)
	if err != nil || a.policy.VerifyIssuedTask(raw, approval, id, a.now) != nil {
		t.Fatalf("independently issued task did not match its approval: %v", err)
	}
	changedApproval := approval
	changedApproval.Request.Proposal.Version = "v26.11.9"
	if err := a.policy.VerifyIssuedTask(raw, changedApproval, id, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted changed approval: %v", err)
	}
	mismatched, err := signInstallTask(changedApproval, id, a.taskKey, a.policy.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.policy.VerifyIssuedTask(mismatched, approval, id, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted a valid signer signature over mismatched parameters: %v", err)
	}
	if err := a.policy.VerifyIssuedTask(raw, approval, id, a.now.Add(10*time.Minute)); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted expired task: %v", err)
	}
	if _, err := protocol.CanonicalV2TaskBytes(raw); err == nil {
		t.Fatal("install approval crossed into the status-task protocol")
	}
	var task installTask
	if err := json.Unmarshal(raw, &task); err != nil {
		t.Fatal(err)
	}
	p := a.proposal
	if task.TaskID != p.TaskID || task.NodeID != p.NodeID || task.Sequence != p.Sequence || task.Operation != "core.install" ||
		task.Payload != (installPayload{Core: "xray", Version: p.Version, ArtifactID: "xray-amd64-" + p.SHA256, ManifestVersion: 7}) ||
		task.IssuedAt != a.now.Format(time.RFC3339) || task.ExpiresAt != a.now.Add(10*time.Minute).Format(time.RFC3339) {
		t.Fatalf("unexpected signed task: %+v", task)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := InitLedger(path); err == nil {
		t.Fatal("could reinitialize an existing ledger")
	}
	reopened, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := a.policy.Issue(t.Context(), reopened, approval, a.taskKey, a.now.Add(time.Minute))
	if err != nil || !bytes.Equal(raw, retry) {
		t.Fatalf("retry returned different task bytes: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), reopened, approval, a.taskKey, a.now.Add(10*time.Minute)); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired replay: %v", err)
	}
	conflicting := a.proposal
	conflicting.Sequence++
	if _, err := a.policy.Issue(t.Context(), reopened, a.approve(t, conflicting), a.taskKey, a.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("old task ID authorized another sequence: %v", err)
	}
}

func TestApprovalRejectsMutationSelfApprovalAndRevocation(t *testing.T) {
	a := newTestAuthority(t)
	_, ledger := newLedger(t)
	approval := a.approve(t, a.proposal)
	for _, change := range []struct {
		name string
		edit func(*Proposal)
	}{
		{"node", func(p *Proposal) { p.NodeID = "other-node" }},
		{"task", func(p *Proposal) { p.TaskID += "-changed" }},
		{"sequence", func(p *Proposal) { p.Sequence++ }},
		{"architecture", func(p *Proposal) { p.Architecture = "arm64" }},
		{"digest", func(p *Proposal) { p.SHA256 = strings.Repeat("b", 64) }},
		{"manifest", func(p *Proposal) { p.ManifestVersion++ }},
		{"version", func(p *Proposal) { p.Version = "v26.11.9" }},
		{"operation", func(p *Proposal) { p.Operation = "core.upgrade" }},
		{"approver", func(p *Proposal) { p.ApproverID = p.RequesterID }},
		{"expires", func(p *Proposal) { p.ExpiresAt++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			edited := approval
			change.edit(&edited.Request.Proposal)
			if _, err := a.policy.Issue(t.Context(), ledger, edited, a.taskKey, a.now); !errors.Is(err, ErrDenied) {
				t.Fatalf("modified approval reached issuance: %v", err)
			}
		})
	}
	if _, err := a.policy.Approve(approval.Request, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("operator signed as approver: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), ledger, approval, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("operator signed an install task: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), ledger, approval, a.taskKey, a.now.Add(-time.Second)); !errors.Is(err, ErrDenied) {
		t.Fatalf("future approval was accepted: %v", err)
	}
	doc := a.policyDoc
	doc.Principals[1].NodeIDs = []string{"other-node"}
	revoked := parseTestPolicy(t, doc)
	if _, err := revoked.Issue(t.Context(), ledger, approval, a.taskKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("old approval still allowed after scope revocation: %v", err)
	}
	var count int
	if err := ledger.db.QueryRow("SELECT count(*) FROM issuances").Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied requests changed ledger: count=%d, err=%v", count, err)
	}
}

func TestConcurrentSlotConsumptionAndStrictPolicy(t *testing.T) {
	a := newTestAuthority(t)
	path, first := newLedger(t)
	second, err := OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	other := a.proposal
	other.TaskID += "-other"
	approvals := []Approval{a.approve(t, a.proposal), a.approve(t, other)}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, ledger := range []*Ledger{first, second} {
		go func() {
			<-start
			_, err := a.policy.Issue(t.Context(), ledger, approvals[i], a.taskKey, a.now)
			results <- err
		}()
	}
	close(start)
	errs := []error{<-results, <-results}
	if !((errs[0] == nil && errors.Is(errs[1], ErrConflict)) || (errs[1] == nil && errors.Is(errs[0], ErrConflict))) {
		t.Fatalf("concurrent slot consumption: %v", errs)
	}
	doc := a.policyDoc
	doc.Principals[1].PublicKey = doc.Principals[0].PublicKey
	if _, err := ParsePolicy(encode(t, doc)); err == nil {
		t.Fatal("policy accepted reused reviewer key")
	}
	proposal := encode(t, a.proposal)
	for _, prefix := range []string{`{"operation":"core.install",`, `{"url":"https://example.invalid/",`, `{"Operation":"core.install",`} {
		raw := append([]byte(prefix), proposal[1:]...)
		if _, err := ParseProposal(raw); err == nil {
			t.Fatalf("accepted ambiguous or extraneous input: %s", prefix)
		}
	}
}
