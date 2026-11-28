package xrayconfig

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/ACnoway/mcui/internal/security"
)

// PanelReality contains REALITY settings, the editable private key, and a copy
// sealed to one node for rendering. The panel API returns PrivateKey only to
// administrators who can edit the node's inbound draft.
type PanelReality struct {
	RealitySettings
	PrivateKey string `json:"private_key"`
	Key        string `json:"key"`
}

// RealitySettings is the non-secret portion of an inbound's REALITY identity.
type RealitySettings struct {
	Target       string   `json:"target"`
	ServerNames  []string `json:"server_names"`
	PublicKey    string   `json:"public_key"`
	ShortIDs     []string `json:"short_ids"`
	Show         bool     `json:"show"`
	Xver         int      `json:"xver"`
	Fingerprint  string   `json:"fingerprint"`
	SpiderX      string   `json:"spider_x"`
	MaxTimeDiff  int64    `json:"max_time_diff"`
	MinClientVer string   `json:"min_client_ver"`
	MaxClientVer string   `json:"max_client_ver"`
}

var realityDNSName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var panelShortID = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,8}$`)
var realityClientVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var realityFingerprint = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true,
	"edge": true, "360": true, "qq": true, "random": true, "randomized": true,
	"randomizednoalpn": true, "unsafe": true,
}

func validRealityName(name string) bool {
	return len(name) <= 253 && realityDNSName.MatchString(name)
}

// Valid validates the signed public settings and sealed key envelope.
func (p RealitySettings) Valid() bool {
	host, port, err := net.SplitHostPort(p.Target)
	if err != nil || host == "" || len(p.Target) > 260 || !security.ValidNodeSecret(p.PublicKey) ||
		len(p.ShortIDs) == 0 || len(p.ShortIDs) > 8 || len(p.ServerNames) == 0 || len(p.ServerNames) > 8 ||
		p.Xver < 0 || p.Xver > 2 || !realityFingerprint[p.Fingerprint] || len(p.SpiderX) > 256 ||
		!strings.HasPrefix(p.SpiderX, "/") || strings.ContainsAny(p.SpiderX, "\r\n\x00") ||
		p.MaxTimeDiff < 0 || p.MaxTimeDiff > 86_400_000 || !validRealityClientVersions(p.MinClientVer, p.MaxClientVer) {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() || !publicIPv4(ip.String()) || ip.String() != host {
		return false
	}
	seen := make(map[string]bool, len(p.ServerNames))
	for _, name := range p.ServerNames {
		if !validRealityName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	seenShortIDs := make(map[string]bool, len(p.ShortIDs))
	for _, id := range p.ShortIDs {
		if !panelShortID.MatchString(id) || strings.Trim(id, "0") == "" || seenShortIDs[id] {
			return false
		}
		seenShortIDs[id] = true
	}
	return true
}

func validRealityClientVersions(minimum, maximum string) bool {
	if (minimum != "" && !realityClientVersion.MatchString(minimum)) || (maximum != "" && !realityClientVersion.MatchString(maximum)) {
		return false
	}
	if minimum == "" || maximum == "" {
		return true
	}
	minParts, maxParts := strings.Split(minimum, "."), strings.Split(maximum, ".")
	for i := range minParts {
		minValue, errMin := strconv.ParseUint(minParts[i], 10, 32)
		maxValue, errMax := strconv.ParseUint(maxParts[i], 10, 32)
		if errMin != nil || errMax != nil {
			return false
		}
		if minValue < maxValue {
			return true
		}
		if minValue > maxValue {
			return false
		}
	}
	return true
}

// ValidRealityTargetInput accepts a DNS name for resolution or a public IPv4.
// The signed REALITY target itself must be a pinned public IPv4.
func ValidRealityTargetInput(target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil || len(target) > 260 {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Is4() && ip.String() == host && publicIPv4(host)
	}
	return validRealityName(host)
}

func (p PanelReality) Valid() bool {
	public, err := RealityPublicKey(p.PrivateKey)
	return p.RealitySettings.Valid() && err == nil && public == p.PublicKey && validPanelBox(p.Key, 32)
}

func (p PanelReality) context(port int) []byte {
	return fmt.Appendf(nil, "MCUI-XRAY-PANEL-REALITY-V1\n%d\n%s", port, p.PublicKey)
}

// NewPanelReality creates a fresh identity and seals its private key to the node.
func NewPanelReality(nodeKey string, port int, target string, names []string) (*PanelReality, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	short := make([]byte, 8)
	if _, err := rand.Read(short); err != nil {
		return nil, err
	}
	privateKey := base64.RawURLEncoding.EncodeToString(key.Bytes())
	settings := RealitySettings{
		Target: target, ServerNames: append([]string(nil), names...), ShortIDs: []string{hex.EncodeToString(short)},
		Show: false, Xver: 0, Fingerprint: "chrome", SpiderX: "/", MaxTimeDiff: 120_000,
	}
	settings.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return NewPanelRealityWithSettings(nodeKey, port, settings, privateKey)
}

// NewPanelRealityWithSettings seals an administrator-supplied X25519 key to
// the node while retaining it in the editable master draft.
func NewPanelRealityWithSettings(nodeKey string, port int, settings RealitySettings, privateKey string) (*PanelReality, error) {
	if port < 1 || port > 65535 || !security.ValidNodeSecret(privateKey) {
		return nil, errors.New("invalid REALITY inbound key or port")
	}
	privateBytes, err := base64.RawURLEncoding.Strict().DecodeString(privateKey)
	if err != nil || len(privateBytes) != 32 || base64.RawURLEncoding.EncodeToString(privateBytes) != privateKey {
		return nil, errors.New("invalid REALITY private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	publicKey := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	if settings.PublicKey != "" && settings.PublicKey != publicKey {
		return nil, errors.New("REALITY public key does not match private key")
	}
	settings.PublicKey = publicKey
	p := &PanelReality{RealitySettings: settings, PrivateKey: privateKey}
	p.Key, err = sealPanelSecret(nodeKey, p.context(port), privateBytes)
	if err != nil {
		return nil, err
	}
	if !p.Valid() {
		return nil, errors.New("invalid REALITY settings")
	}
	return p, nil
}

func (p PanelReality) open(private hpke.PrivateKey, port int) (string, error) {
	if !p.Valid() {
		return "", errors.New("invalid REALITY identity")
	}
	data, err := openPanelSecret(private, p.context(port), p.Key)
	if err != nil || len(data) != 32 {
		return "", errors.New("cannot open REALITY identity")
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	public, err := RealityPublicKey(encoded)
	if err != nil || public != p.PublicKey || encoded != p.PrivateKey {
		return "", errors.New("REALITY public key mismatch")
	}
	return encoded, nil
}
