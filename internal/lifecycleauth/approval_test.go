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
	taskKey    ed25519.PrivateKey
	now        time.Time
	proposal   Proposal
}

func newTestAuthority(t *testing.T) testAuthority {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 2)
	public := make([]string, len(keys))
	for i := range keys {
		pub, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		keys[i], public[i] = private, base64.StdEncoding.EncodeToString(pub)
	}
	doc := policyDocument{SchemaVersion: 1, SigningKeyID: "xray-install-test", SigningPublicKey: public[1],
		Principals: []Principal{
			{ID: "operator-1", Role: "operator", PublicKey: public[0], NodeIDs: []string{"test-node"}},
		},
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	p := Proposal{
		SchemaVersion: 2, Operation: "core.install", Core: "xray", TaskID: "test-install-task-000001",
		NodeID: "test-node", Sequence: 9, Version: "v26.10.31", Architecture: "amd64",
		SHA256: strings.Repeat("3a", 32), ManifestVersion: 7, RequesterID: "operator-1",
		SigningKeyID: doc.SigningKeyID, CreatedAt: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(25 * time.Minute).Unix(),
	}
	return testAuthority{policyDoc: doc, policy: parseTestPolicy(t, doc), requestKey: keys[0],
		taskKey: keys[1], now: now, proposal: p}
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

func (a testAuthority) request(t *testing.T, p Proposal) Request {
	t.Helper()
	request, err := a.policy.SignRequest(p, a.requestKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	raw := encode(t, request)
	request, err = ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return request
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

func TestIssueXrayControlBindsActionAndInstalledRelease(t *testing.T) {
	a := newTestAuthority(t)
	_, ledger := newLedger(t)
	p := a.proposal
	p.SchemaVersion, p.Operation, p.ManifestVersion = ControlProposalVersion, "core.stop", 0
	request := a.request(t, p)
	raw, err := a.policy.Issue(t.Context(), ledger, request, a.taskKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.policy.VerifyIssuedTask(raw, request, a.now)
	if err != nil {
		t.Fatal(err)
	}
	task, err := a.policy.InstallKey().Verify(raw)
	if err != nil || !task.Matches(p, id) || task.SignedManifest {
		t.Fatalf("verified control task = %+v, %v", task, err)
	}
	changed := request
	changed.Proposal.Operation = "core.start"
	mismatch, err := signInstallTask(changed, id, a.taskKey, a.policy.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.policy.VerifyIssuedTask(mismatch, request, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted different signed action: %v", err)
	}
	p.ManifestVersion = 1
	if _, err := a.policy.SignRequest(p, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted artifact metadata on a control proposal: %v", err)
	}
}

func TestIssueXrayVersionChangesBindBothReleases(t *testing.T) {
	a := newTestAuthority(t)
	_, ledger := newLedger(t)
	p := a.proposal
	p.SchemaVersion, p.Operation = ChangeProposalVersion, "core.downgrade"
	p.CurrentVersion, p.CurrentSHA256 = "v26.11.9", strings.Repeat("b", 64)
	missingDigest, wrongDirection := p, p
	missingDigest.CurrentSHA256 = ""
	wrongDirection.Operation = "core.upgrade"
	for _, invalid := range []Proposal{missingDigest, wrongDirection} {
		if _, err := a.policy.SignRequest(invalid, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
			t.Fatalf("accepted invalid version-change proposal: %+v (%v)", invalid, err)
		}
	}
	request := a.request(t, p)
	raw, err := a.policy.Issue(t.Context(), ledger, request, a.taskKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.policy.VerifyIssuedTask(raw, request, a.now)
	if err != nil {
		t.Fatal(err)
	}
	task, err := a.policy.InstallKey().Verify(raw)
	if err != nil || !task.Matches(p, id) || !task.SignedManifest {
		t.Fatalf("verified downgrade: %+v, %v", task, err)
	}
	changed := request
	changed.Proposal.CurrentSHA256 = strings.Repeat("c", 64)
	mismatch, err := signInstallTask(changed, id, a.taskKey, a.policy.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.policy.VerifyIssuedTask(mismatch, request, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted changed installed digest: %v", err)
	}
}

func TestIssueExactInstallAndReplayAfterReopen(t *testing.T) {
	a := newTestAuthority(t)
	path, ledger := newLedger(t)
	request := a.request(t, a.proposal)
	raw, err := a.policy.Issue(t.Context(), ledger, request, a.taskKey, a.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.Verify(protocol.Task, raw, a.taskKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	id, err := a.policy.VerifyIssuedTask(raw, request, a.now)
	if err != nil || len(id) != 64 {
		t.Fatalf("independently issued task did not match its request: %v", err)
	}
	changedRequest := request
	changedRequest.Proposal.Version = "v26.11.9"
	if _, err := a.policy.VerifyIssuedTask(raw, changedRequest, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted changed request: %v", err)
	}
	mismatched, err := signInstallTask(changedRequest, id, a.taskKey, a.policy.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.policy.VerifyIssuedTask(mismatched, request, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted a valid signer signature over mismatched parameters: %v", err)
	}
	if _, err := a.policy.VerifyIssuedTask(raw, request, a.now.Add(10*time.Minute)); !errors.Is(err, ErrDenied) {
		t.Fatalf("accepted expired task: %v", err)
	}
	if _, err := protocol.CanonicalV2TaskBytes(raw); err == nil {
		t.Fatal("install task crossed into the status-task protocol")
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
	retry, err := a.policy.Issue(t.Context(), reopened, request, a.taskKey, a.now.Add(time.Minute))
	if err != nil || !bytes.Equal(raw, retry) {
		t.Fatalf("retry returned different task bytes: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), reopened, request, a.taskKey, a.now.Add(10*time.Minute)); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired replay: %v", err)
	}
	conflicting := a.proposal
	conflicting.Sequence++
	if _, err := a.policy.Issue(t.Context(), reopened, a.request(t, conflicting), a.taskKey, a.now); !errors.Is(err, ErrConflict) {
		t.Fatalf("old task ID authorized another sequence: %v", err)
	}
}

func TestRequestRejectsMutationAndRevocation(t *testing.T) {
	a := newTestAuthority(t)
	_, ledger := newLedger(t)
	request := a.request(t, a.proposal)
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
		{"legacy approver", func(p *Proposal) { p.ApproverID = "security-1" }},
		{"expires", func(p *Proposal) { p.ExpiresAt++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			edited := request
			change.edit(&edited.Proposal)
			if _, err := a.policy.Issue(t.Context(), ledger, edited, a.taskKey, a.now); !errors.Is(err, ErrDenied) {
				t.Fatalf("modified request reached issuance: %v", err)
			}
		})
	}
	edited := request
	edited.RequestedAt--
	if _, err := a.policy.Issue(t.Context(), ledger, edited, a.taskKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("modified request time reached issuance: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), ledger, request, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("operator signed an install task: %v", err)
	}
	if _, err := a.policy.Issue(t.Context(), ledger, request, a.taskKey, a.now.Add(-time.Second)); !errors.Is(err, ErrDenied) {
		t.Fatalf("future request was accepted: %v", err)
	}
	doc := a.policyDoc
	doc.Principals[0].NodeIDs = []string{"other-node"}
	revoked := parseTestPolicy(t, doc)
	if _, err := revoked.Issue(t.Context(), ledger, request, a.taskKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("old request still allowed after scope revocation: %v", err)
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
	requests := []Request{a.request(t, a.proposal), a.request(t, other)}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, ledger := range []*Ledger{first, second} {
		go func() {
			<-start
			_, err := a.policy.Issue(t.Context(), ledger, requests[i], a.taskKey, a.now)
			results <- err
		}()
	}
	close(start)
	errs := []error{<-results, <-results}
	if !((errs[0] == nil && errors.Is(errs[1], ErrConflict)) || (errs[1] == nil && errors.Is(errs[0], ErrConflict))) {
		t.Fatalf("concurrent slot consumption: %v", errs)
	}
	doc := a.policyDoc
	doc.Principals[0].PublicKey = doc.SigningPublicKey
	if _, err := ParsePolicy(encode(t, doc)); err == nil {
		t.Fatal("policy accepted a reused signing key")
	}
	proposal := encode(t, a.proposal)
	for _, prefix := range []string{`{"operation":"core.install",`, `{"url":"https://example.invalid/",`, `{"Operation":"core.install",`} {
		raw := append([]byte(prefix), proposal[1:]...)
		if _, err := ParseProposal(raw); err == nil {
			t.Fatalf("accepted ambiguous or extraneous input: %s", prefix)
		}
	}
}

func TestLegacyProposalCanBeReadButCannotBeSigned(t *testing.T) {
	a := newTestAuthority(t)
	legacy := a.proposal
	legacy.SchemaVersion = 1
	legacy.ApproverID = "former-approver"
	if parsed, err := ParseProposal(encode(t, legacy)); err != nil || parsed != legacy || !a.policy.AllowsProposal(parsed) {
		t.Fatalf("could not read stored legacy proposal: %+v, %v", parsed, err)
	}
	if _, err := a.policy.SignRequest(legacy, a.requestKey, a.now); !errors.Is(err, ErrDenied) {
		t.Fatalf("legacy proposal was signed as a new request: %v", err)
	}
}
