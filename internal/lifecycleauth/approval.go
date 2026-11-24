// Package lifecycleauth verifies scoped operator requests and independently
// signs the requested Xray installation tasks.
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
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const (
	maxSequence                    = 9007199254740991
	maxProofBytes                  = 16 << 10
	maxPolicySize                  = 256 << 10
	maxUnixTime                    = 253402300799
	proposalTTL                    = 30 * time.Minute
	taskTTL                        = 10 * time.Minute
	requestDomain                  = "MCUI-XRAY-INSTALL-REQUEST-V2\n"
	controlRequestDomain           = "MCUI-XRAY-CONTROL-REQUEST-V1\n"
	changeRequestDomain            = "MCUI-XRAY-CHANGE-REQUEST-V1\n"
	SignedManifestProposalVersion  = 3
	ControlProposalVersion         = 4
	ChangeProposalVersion          = 5
	ConfigProposalVersion          = 6
	OfficialReleaseProposalVersion = 7
)

var (
	ErrDenied     = errors.New("Xray install authorization denied")
	ErrConflict   = errors.New("install task ID, request or node sequence was already used")
	identifier    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Proposal struct {
	SchemaVersion   int                  `json:"schema_version"`
	Operation       string               `json:"operation"`
	Core            string               `json:"core"`
	TaskID          string               `json:"task_id"`
	NodeID          string               `json:"node_id"`
	Sequence        int64                `json:"sequence"`
	Version         string               `json:"version"`
	Architecture    string               `json:"architecture"`
	SHA256          string               `json:"sha256"`
	ManifestVersion int64                `json:"manifest_version,omitempty"`
	CurrentVersion  string               `json:"current_version,omitempty"`
	CurrentSHA256   string               `json:"current_sha256,omitempty"`
	RequesterID     string               `json:"requester_id"`
	ApproverID      string               `json:"approver_id,omitempty"` // Retained for stored V1 proposals.
	SigningKeyID    string               `json:"signing_key_id"`
	CreatedAt       int64                `json:"created_at"`
	ExpiresAt       int64                `json:"expires_at"`
	Config          xrayconfig.Reference `json:"config,omitzero"`
	Plan            string               `json:"plan,omitempty"`
}

type Request struct {
	Proposal    Proposal `json:"proposal"`
	RequestedAt int64    `json:"requested_at"`
	Signature   string   `json:"signature"`
}

type requestContent struct {
	Proposal    Proposal `json:"proposal"`
	RequestedAt int64    `json:"requested_at"`
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
	Panel            *PanelScope `json:"panel,omitempty"`
}

type PanelScope struct {
	AllNodes bool     `json:"all_nodes"`
	NodeIDs  []string `json:"node_ids,omitempty"`
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
	panel      *PanelScope
}

func ParsePolicy(raw []byte) (*Policy, error) {
	var doc policyDocument
	if len(raw) > maxPolicySize || jsonv2.Unmarshal(raw, &doc, jsonv2.RejectUnknownMembers(true)) != nil ||
		doc.SchemaVersion != 1 || !identifier.MatchString(doc.SigningKeyID) || (len(doc.Principals) == 0 && doc.Panel == nil) {
		return nil, errors.New("invalid Xray install authorization policy")
	}
	signingKey, err := publicKey(doc.SigningPublicKey)
	if err != nil {
		return nil, err
	}
	if doc.Panel != nil {
		if doc.Panel.AllNodes == (len(doc.Panel.NodeIDs) != 0) {
			return nil, errors.New("panel policy requires either all_nodes or an explicit node list")
		}
		for i, id := range doc.Panel.NodeIDs {
			if !security.ValidNodeID(id) || slices.Contains(doc.Panel.NodeIDs[:i], id) {
				return nil, errors.New("invalid or duplicate panel node ID")
			}
		}
	}
	policy := &Policy{keyID: doc.SigningKeyID, signingKey: signingKey, principals: make(map[string]principal), panel: doc.Panel}
	keys := map[string]bool{string(signingKey): true}
	for _, actor := range doc.Principals {
		key, err := publicKey(actor.PublicKey)
		if err != nil || keys[string(key)] || !identifier.MatchString(actor.ID) ||
			(actor.Role != "operator" && actor.Role != "security_admin") || len(actor.NodeIDs) == 0 {
			return nil, errors.New("invalid or reused Xray authorization principal or key")
		}
		if _, exists := policy.principals[actor.ID]; exists {
			return nil, errors.New("duplicate Xray authorization principal")
		}
		nodes := make(map[string]bool, len(actor.NodeIDs))
		for _, nodeID := range actor.NodeIDs {
			if !security.ValidNodeID(nodeID) || nodes[nodeID] {
				return nil, errors.New("invalid or duplicate authorization node scope")
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
		return nil, errors.New("authorization policy needs canonical Base64 Ed25519 public keys")
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
	if len(raw) > maxProofBytes || jsonv2.Unmarshal(raw, &request, jsonv2.RejectUnknownMembers(true)) != nil ||
		!request.Proposal.singleOperator() || !request.Proposal.valid() {
		return Request{}, ErrDenied
	}
	return request, nil
}

func (p Proposal) valid() bool {
	validSchema := (p.singleOperator() && p.ApproverID == "") ||
		(p.SchemaVersion == 1 && identifier.MatchString(p.ApproverID) && p.ApproverID != p.RequesterID)
	return validSchema && p.validOperation() && p.Core == "xray" &&
		taskIDPattern.MatchString(p.TaskID) && security.ValidNodeID(p.NodeID) &&
		p.Sequence >= 1 && p.Sequence <= maxSequence &&
		corecatalog.ValidXrayRelease(p.Version, p.SHA256) && (p.Architecture == "amd64" || p.Architecture == "arm64") &&
		identifier.MatchString(p.RequesterID) &&
		identifier.MatchString(p.SigningKeyID) && p.CreatedAt > 0 && p.ExpiresAt <= maxUnixTime &&
		p.CreatedAt < p.ExpiresAt && p.ExpiresAt-p.CreatedAt <= int64(proposalTTL/time.Second)
}

func (p Proposal) validOperation() bool {
	noCurrent := p.CurrentVersion == "" && p.CurrentSHA256 == ""
	validManifest := p.ManifestVersion >= 1 && p.ManifestVersion <= maxSequence
	if p.Operation != xrayconfig.Operation && (p.Config != (xrayconfig.Reference{}) || p.Plan != "") {
		return false
	}
	switch p.Operation {
	case "core.install":
		legacy := p.SchemaVersion >= 1 && p.SchemaVersion <= SignedManifestProposalVersion && validManifest
		return noCurrent && (legacy || p.SchemaVersion == OfficialReleaseProposalVersion && p.ManifestVersion == 0)
	case "core.start", "core.stop":
		return p.SchemaVersion == ControlProposalVersion && noCurrent && p.ManifestVersion == 0
	case "core.upgrade", "core.downgrade":
		legacy := p.SchemaVersion == ChangeProposalVersion && validManifest
		return (legacy || p.SchemaVersion == OfficialReleaseProposalVersion && p.ManifestVersion == 0) &&
			validVersionChange(p.Operation, p.CurrentVersion, p.CurrentSHA256, p.Version, p.SHA256)
	case "core.uninstall":
		return p.SchemaVersion == ChangeProposalVersion && noCurrent && p.ManifestVersion == 0
	case xrayconfig.Operation:
		if p.Plan != "" {
			if _, err := xrayconfig.ParseConfiguration(p.Plan); err != nil {
				return false
			}
		}
		return p.SchemaVersion == ConfigProposalVersion && noCurrent && (p.ManifestVersion == 0 || validManifest) &&
			p.Version == xrayconfig.Version && p.Architecture == xrayconfig.Architecture && p.Config.Valid()
	default:
		return false
	}
}

func (p Proposal) singleOperator() bool {
	return p.SchemaVersion >= 2 && p.SchemaVersion <= OfficialReleaseProposalVersion
}

func (p Proposal) requestDomain() string {
	switch p.SchemaVersion {
	case ChangeProposalVersion:
		return changeRequestDomain
	case ControlProposalVersion:
		return controlRequestDomain
	default:
		return requestDomain
	}
}

func (policy *Policy) requesterKey(p Proposal) ed25519.PublicKey {
	if policy == nil || !p.valid() || p.Operation == xrayconfig.Operation || p.SigningKeyID != policy.keyID {
		return nil
	}
	operator := policy.principals[p.RequesterID]
	if operator.policy.Role != "operator" || !slices.Contains(operator.policy.NodeIDs, p.NodeID) {
		return nil
	}
	return operator.key
}

// AllowsProposal checks the immutable proposal and current operator scope.
func (policy *Policy) AllowsProposal(p Proposal) bool {
	return policy.requesterKey(p) != nil
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
	at := now.Unix()
	if !p.singleOperator() || !matchesPrivate(key, policy.requesterKey(p)) || at < p.CreatedAt || at >= p.ExpiresAt {
		return Request{}, ErrDenied
	}
	message, err := signingBytes(p.requestDomain(), requestContent{Proposal: p, RequestedAt: at})
	if err != nil {
		return Request{}, err
	}
	return Request{Proposal: p, RequestedAt: at, Signature: sign(key, message)}, nil
}

// VerifyRequest returns the digest of the exact request eligible for issuance.
func (policy *Policy) VerifyRequest(r Request, now time.Time) (string, error) {
	p := r.Proposal
	operator := policy.requesterKey(p)
	if !p.singleOperator() || operator == nil || r.RequestedAt < p.CreatedAt ||
		r.RequestedAt > now.Unix() || now.Unix() >= r.taskExpiry() {
		return "", ErrDenied
	}
	message, err := signingBytes(p.requestDomain(), requestContent{Proposal: p, RequestedAt: r.RequestedAt})
	if err != nil || !verify(operator, message, r.Signature) {
		return "", ErrDenied
	}
	evidence, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(evidence)
	return hex.EncodeToString(hash[:]), nil
}

func (r Request) taskExpiry() int64 {
	return min(r.Proposal.ExpiresAt, r.RequestedAt+int64(taskTTL/time.Second))
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
