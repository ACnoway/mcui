// Package lifecycleauth verifies independent, scoped approvals for Xray
// installation and issues the exact approved task.
package lifecycleauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/security"
)

const (
	maxSequence   = 9007199254740991
	maxProofBytes = 16 << 10
	maxPolicySize = 256 << 10
	maxUnixTime   = 253402300799
	approvalTTL   = 30 * time.Minute
	taskTTL       = 10 * time.Minute
	requestDomain = "MCUI-XRAY-INSTALL-REQUEST-V1\n"
	approveDomain = "MCUI-XRAY-INSTALL-APPROVAL-V1\n"
)

var (
	ErrDenied     = errors.New("Xray install authorization denied")
	ErrConflict   = errors.New("install task ID, approval or node sequence was already used")
	identifier    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
)

type Proposal struct {
	SchemaVersion   int    `json:"schema_version"`
	Operation       string `json:"operation"`
	Core            string `json:"core"`
	TaskID          string `json:"task_id"`
	NodeID          string `json:"node_id"`
	Sequence        int64  `json:"sequence"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
	SHA256          string `json:"sha256"`
	ManifestVersion int64  `json:"manifest_version"`
	RequesterID     string `json:"requester_id"`
	ApproverID      string `json:"approver_id"`
	SigningKeyID    string `json:"signing_key_id"`
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

type Request struct {
	Proposal  Proposal `json:"proposal"`
	Signature string   `json:"signature"`
}

type Approval struct {
	Request    Request `json:"request"`
	ApprovedAt int64   `json:"approved_at"`
	Signature  string  `json:"signature"`
}

type approvalContent struct {
	Request    Request `json:"request"`
	ApprovedAt int64   `json:"approved_at"`
}

type Principal struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	PublicKey string   `json:"public_key"`
	NodeIDs   []string `json:"node_ids"`
}

type policyDocument struct {
	SchemaVersion    int         `json:"schema_version"`
	SigningKeyID     string      `json:"signing_key_id"`
	SigningPublicKey string      `json:"signing_public_key"`
	Principals       []Principal `json:"principals"`
}

type principal struct {
	policy Principal
	key    ed25519.PublicKey
}

// Policy is supplied by the signing authority and kept outside the panel's
// writable state. Each actor and the purpose-specific signer have unique keys.
type Policy struct {
	keyID      string
	signingKey ed25519.PublicKey
	principals map[string]principal
}

func ParsePolicy(raw []byte) (*Policy, error) {
	var doc policyDocument
	if len(raw) > maxPolicySize || jsonv2.Unmarshal(raw, &doc, jsonv2.RejectUnknownMembers(true)) != nil ||
		doc.SchemaVersion != 1 || !identifier.MatchString(doc.SigningKeyID) || len(doc.Principals) < 2 {
		return nil, errors.New("invalid Xray install authorization policy")
	}
	signingKey, err := publicKey(doc.SigningPublicKey)
	if err != nil {
		return nil, err
	}
	policy := &Policy{keyID: doc.SigningKeyID, signingKey: signingKey, principals: make(map[string]principal)}
	keys := map[string]bool{string(signingKey): true}
	for _, actor := range doc.Principals {
		key, err := publicKey(actor.PublicKey)
		if err != nil || keys[string(key)] || !identifier.MatchString(actor.ID) ||
			(actor.Role != "operator" && actor.Role != "security_admin") || len(actor.NodeIDs) == 0 {
			return nil, errors.New("invalid or reused Xray approval principal or key")
		}
		if _, exists := policy.principals[actor.ID]; exists {
			return nil, errors.New("duplicate Xray approval principal")
		}
		nodes := make(map[string]bool, len(actor.NodeIDs))
		for _, nodeID := range actor.NodeIDs {
			if !security.ValidNodeID(nodeID) || nodes[nodeID] {
				return nil, errors.New("invalid or duplicate approval node scope")
			}
			nodes[nodeID] = true
		}
		keys[string(key)] = true
		policy.principals[actor.ID] = principal{policy: actor, key: key}
	}
	return policy, nil
}

func publicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != value ||
		bytes.Equal(raw, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("approval policy needs canonical Base64 Ed25519 public keys")
	}
	return ed25519.PublicKey(raw), nil
}

func ParseProposal(raw []byte) (Proposal, error) {
	var proposal Proposal
	if len(raw) > maxProofBytes || jsonv2.Unmarshal(raw, &proposal, jsonv2.RejectUnknownMembers(true)) != nil || !proposal.valid() {
		return Proposal{}, ErrDenied
	}
	return proposal, nil
}

func ParseRequest(raw []byte) (Request, error) {
	var request Request
	if len(raw) > maxProofBytes || jsonv2.Unmarshal(raw, &request, jsonv2.RejectUnknownMembers(true)) != nil || !request.Proposal.valid() {
		return Request{}, ErrDenied
	}
	return request, nil
}

func ParseApproval(raw []byte) (Approval, error) {
	var approval Approval
	if len(raw) > maxProofBytes || jsonv2.Unmarshal(raw, &approval, jsonv2.RejectUnknownMembers(true)) != nil || !approval.Request.Proposal.valid() {
		return Approval{}, ErrDenied
	}
	return approval, nil
}

func (p Proposal) valid() bool {
	return p.SchemaVersion == 1 && p.Operation == "core.install" && p.Core == "xray" &&
		taskIDPattern.MatchString(p.TaskID) && security.ValidNodeID(p.NodeID) &&
		p.Sequence >= 1 && p.Sequence <= maxSequence && p.ManifestVersion >= 1 && p.ManifestVersion <= maxSequence &&
		corecatalog.ValidXrayRelease(p.Version, p.SHA256) && (p.Architecture == "amd64" || p.Architecture == "arm64") &&
		identifier.MatchString(p.RequesterID) && identifier.MatchString(p.ApproverID) && p.RequesterID != p.ApproverID &&
		identifier.MatchString(p.SigningKeyID) && p.CreatedAt > 0 && p.ExpiresAt <= maxUnixTime &&
		p.CreatedAt < p.ExpiresAt && p.ExpiresAt-p.CreatedAt <= int64(approvalTTL/time.Second)
}

func (policy *Policy) reviewers(p Proposal) (ed25519.PublicKey, ed25519.PublicKey, error) {
	if policy == nil || !p.valid() || p.SigningKeyID != policy.keyID {
		return nil, nil, ErrDenied
	}
	operator, approver := policy.principals[p.RequesterID], policy.principals[p.ApproverID]
	if operator.policy.Role != "operator" || approver.policy.Role != "security_admin" ||
		!slices.Contains(operator.policy.NodeIDs, p.NodeID) || !slices.Contains(approver.policy.NodeIDs, p.NodeID) {
		return nil, nil, ErrDenied
	}
	return operator.key, approver.key, nil
}

// AllowsProposal checks the immutable proposal and the independent actor scopes.
func (policy *Policy) AllowsProposal(p Proposal) bool {
	_, _, err := policy.reviewers(p)
	return err == nil
}

func (policy *Policy) SigningKeyID() string { return policy.keyID }

// UsesPublicKey checks separation from other trusted signing purposes.
func (policy *Policy) UsesPublicKey(key ed25519.PublicKey) bool {
	if bytes.Equal(policy.signingKey, key) {
		return true
	}
	for _, actor := range policy.principals {
		if bytes.Equal(actor.key, key) {
			return true
		}
	}
	return false
}

func (policy *Policy) SignRequest(p Proposal, key ed25519.PrivateKey, now time.Time) (Request, error) {
	operator, _, err := policy.reviewers(p)
	if err != nil || !matchesPrivate(key, operator) || now.IsZero() || now.Unix() < p.CreatedAt || now.Unix() >= p.ExpiresAt {
		return Request{}, ErrDenied
	}
	message, err := signingBytes(requestDomain, p)
	if err != nil {
		return Request{}, err
	}
	return Request{Proposal: p, Signature: sign(key, message)}, nil
}

func (policy *Policy) VerifyRequest(r Request, now time.Time) error {
	p := r.Proposal
	operator, _, err := policy.reviewers(p)
	if err != nil || now.IsZero() || now.Unix() < p.CreatedAt || now.Unix() >= p.ExpiresAt {
		return ErrDenied
	}
	message, err := signingBytes(requestDomain, p)
	if err != nil || !verify(operator, message, r.Signature) {
		return ErrDenied
	}
	return nil
}

func (policy *Policy) Approve(r Request, key ed25519.PrivateKey, now time.Time) (Approval, error) {
	if err := policy.VerifyRequest(r, now); err != nil {
		return Approval{}, err
	}
	approver := policy.principals[r.Proposal.ApproverID].key
	if !matchesPrivate(key, approver) {
		return Approval{}, ErrDenied
	}
	message, err := signingBytes(approveDomain, approvalContent{Request: r, ApprovedAt: now.Unix()})
	if err != nil {
		return Approval{}, err
	}
	return Approval{Request: r, ApprovedAt: now.Unix(), Signature: sign(key, message)}, nil
}

func (policy *Policy) verifyApproval(a Approval, now time.Time) error {
	if err := policy.VerifyRequest(a.Request, now); err != nil {
		return err
	}
	if a.ApprovedAt < a.Request.Proposal.CreatedAt || a.ApprovedAt > now.Unix() || now.Unix() >= a.taskExpiry() {
		return ErrDenied
	}
	message, err := signingBytes(approveDomain, approvalContent{Request: a.Request, ApprovedAt: a.ApprovedAt})
	approver := policy.principals[a.Request.Proposal.ApproverID].key
	if err != nil || !verify(approver, message, a.Signature) {
		return ErrDenied
	}
	return nil
}

// VerifyApproval identifies the exact approval that an independent signer
// can consume while the policy and validity window still allow it.
func (policy *Policy) VerifyApproval(a Approval, now time.Time) (string, error) {
	if err := policy.verifyApproval(a, now); err != nil {
		return "", err
	}
	evidence, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(evidence)
	return hex.EncodeToString(hash[:]), nil
}

func (a Approval) taskExpiry() int64 {
	return min(a.Request.Proposal.ExpiresAt, a.ApprovedAt+int64(taskTTL/time.Second))
}

func signingBytes(domain string, value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

func matchesPrivate(private ed25519.PrivateKey, public ed25519.PublicKey) bool {
	return len(private) == ed25519.PrivateKeySize && len(public) == ed25519.PublicKeySize &&
		bytes.Equal(private[ed25519.SeedSize:], public) &&
		bytes.Equal(private, ed25519.NewKeyFromSeed(private[:ed25519.SeedSize]))
}

func sign(private ed25519.PrivateKey, message []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, message))
}

func verify(public ed25519.PublicKey, message []byte, encoded string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return err == nil && len(raw) == ed25519.SignatureSize && base64.StdEncoding.EncodeToString(raw) == encoded &&
		ed25519.Verify(public, message, raw)
}
