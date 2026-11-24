package lifecycleauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

func NewSingleAdminPolicy(keyID string, publicKey ed25519.PublicKey) (*Policy, error) {
	raw, err := json.Marshal(policyDocument{
		SchemaVersion: 1, SigningKeyID: keyID, SigningPublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Panel: &PanelScope{AllNodes: true},
	})
	if err != nil {
		return nil, err
	}
	return ParsePolicy(raw)
}

type PanelSigner struct {
	policy *Policy
	ledger *Ledger
	key    ed25519.PrivateKey
	now    func() (time.Time, error)
}

func NewPanelSigner(policy *Policy, ledger *Ledger, key ed25519.PrivateKey, now func() (time.Time, error)) (*PanelSigner, error) {
	if !policy.HasPanelScope() || ledger == nil || !matchesPrivate(key, policy.signingKey) || now == nil {
		return nil, errors.New("incomplete panel Xray signer configuration")
	}
	return &PanelSigner{policy: policy, ledger: ledger, key: key, now: now}, nil
}

func (s *PanelSigner) Issue(ctx context.Context, proposal Proposal) ([]byte, error) {
	if _, _, err := s.policy.PanelEvidence(proposal); err != nil {
		return nil, err
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	return s.policy.IssuePanel(ctx, s.ledger, proposal, s.key, now)
}

func (p *Policy) HasPanelScope() bool { return p != nil && p.panel != nil }

func (p *Policy) AllowsPanelNode(node string) bool {
	if !p.HasPanelScope() {
		return false
	}
	if p.panel.AllNodes {
		return true
	}
	for _, id := range p.panel.NodeIDs {
		if node == id {
			return true
		}
	}
	return false
}

func (policy *Policy) PanelEvidence(p Proposal) (string, []byte, error) {
	if !policy.AllowsPanelNode(p.NodeID) {
		return "", nil, ErrDenied
	}
	return policy.panelEvidence(p)
}

func (policy *Policy) panelEvidence(p Proposal) (string, []byte, error) {
	if policy == nil || !p.valid() || p.SchemaVersion < SignedManifestProposalVersion || p.SigningKeyID != policy.keyID {
		return "", nil, ErrDenied
	}
	evidence, err := signingBytes("MCUI-XRAY-PANEL-PROPOSAL-V1\n", p)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(evidence)
	return hex.EncodeToString(sum[:]), evidence, nil
}

func (policy *Policy) VerifyPanelTask(p Proposal, raw []byte) (InstallTask, error) {
	id, _, err := policy.panelEvidence(p)
	if err != nil {
		return InstallTask{}, err
	}
	task, err := policy.InstallKey().Verify(raw)
	r := Request{Proposal: p, RequestedAt: p.CreatedAt}
	if err != nil || !task.Matches(p, id) || task.NotBefore.Unix() != p.CreatedAt || task.ExpiresAt.Unix() != r.taskExpiry() {
		return InstallTask{}, ErrDenied
	}
	return task, nil
}

// IssuePanel consumes a panel-authenticated proposal and signs its exact
// release version and digest with the purpose-specific Core task key.
func (policy *Policy) IssuePanel(ctx context.Context, ledger *Ledger, p Proposal, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	id, evidence, err := policy.PanelEvidence(p)
	request := Request{Proposal: p, RequestedAt: p.CreatedAt}
	if err != nil || ledger == nil || ledger.db == nil || !matchesPrivate(key, policy.signingKey) ||
		now.Unix() < p.CreatedAt || now.Unix() >= request.taskExpiry() {
		return nil, ErrDenied
	}
	task, err := signInstallTask(request, id, key, policy.signingKey)
	if err != nil {
		return nil, err
	}
	return ledger.consume(ctx, p, id, evidence, task)
}
