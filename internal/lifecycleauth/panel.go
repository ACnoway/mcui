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

	"github.com/ACnoway/mcui/internal/artifacttrust"
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
	policy  *Policy
	ledger  *Ledger
	key     ed25519.PrivateKey
	now     func() (time.Time, error)
	current func(context.Context) (artifacttrust.Manifest, error)
}

func NewPanelSigner(policy *Policy, ledger *Ledger, key ed25519.PrivateKey, now func() (time.Time, error), current func(context.Context) (artifacttrust.Manifest, error)) (*PanelSigner, error) {
	if !policy.HasPanelScope() || ledger == nil || !matchesPrivate(key, policy.signingKey) || now == nil || current == nil {
		return nil, errors.New("incomplete panel Xray signer configuration")
	}
	return &PanelSigner{policy: policy, ledger: ledger, key: key, now: now, current: current}, nil
}

func (s *PanelSigner) Manifest(ctx context.Context) (artifacttrust.Manifest, error) {
	return s.current(ctx)
}

func (s *PanelSigner) Issue(ctx context.Context, proposal Proposal) ([]byte, error) {
	if _, _, err := s.policy.PanelEvidence(proposal); err != nil {
		return nil, err
	}
	var manifest artifacttrust.Manifest
	if !IsControlOperation(proposal.Operation) {
		var err error
		manifest, err = s.Manifest(ctx)
		if err != nil {
			return nil, err
		}
	}
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	return s.policy.IssuePanel(ctx, s.ledger, proposal, s.key, now, manifest)
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

// IssuePanel binds a reserved proposal to the latest approved manifest and
// consumes the same durable task/sequence constraints as offline issuance.
func (policy *Policy) IssuePanel(ctx context.Context, ledger *Ledger, p Proposal, key ed25519.PrivateKey, now time.Time, manifest artifacttrust.Manifest) ([]byte, error) {
	id, evidence, err := policy.PanelEvidence(p)
	request := Request{Proposal: p, RequestedAt: p.CreatedAt}
	if err != nil || ledger == nil || ledger.db == nil || !matchesPrivate(key, policy.signingKey) ||
		now.Unix() < p.CreatedAt || now.Unix() >= request.taskExpiry() {
		return nil, ErrDenied
	}
	if !IsControlOperation(p.Operation) {
		var approved bool
		for _, entry := range manifest.Artifacts {
			if entry.Component == "xray" && entry.Architecture == p.Architecture && entry.Version == p.Version && entry.SHA256 == p.SHA256 {
				approved = true
				break
			}
		}
		if !approved || manifest.ManifestVersion != p.ManifestVersion || !now.Before(manifest.ExpiresAt) {
			return nil, ErrDenied
		}
	}
	task, err := signInstallTask(request, id, key, policy.signingKey)
	if err != nil {
		return nil, err
	}
	return ledger.consume(ctx, p, id, evidence, task)
}
