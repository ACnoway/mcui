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

	"github.com/ACnoway/mcui/internal/security"
)

// PanelReality contains public REALITY settings and a private key sealed to one node.
// The enclosing configuration is signed and must not expose Key in subscriptions.
type PanelReality struct {
	RealitySettings
	Key string `json:"key"`
}

// RealitySettings is the non-secret portion of an inbound's REALITY identity.
type RealitySettings struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"server_names"`
	PublicKey   string   `json:"public_key"`
	ShortID     string   `json:"short_id"`
}

var realityDNSName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var panelShortID = regexp.MustCompile(`^(?:[0-9a-f]{2}){1,8}$`)

func validRealityName(name string) bool {
	return len(name) <= 253 && realityDNSName.MatchString(name)
}

// Valid validates the signed public settings and sealed key envelope.
func (p RealitySettings) Valid() bool {
	host, port, err := net.SplitHostPort(p.Target)
	if err != nil || host == "" || len(p.Target) > 260 || !security.ValidNodeSecret(p.PublicKey) ||
		!panelShortID.MatchString(p.ShortID) || len(p.ServerNames) == 0 || len(p.ServerNames) > 8 {
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

func (p PanelReality) Valid() bool { return p.RealitySettings.Valid() && validPanelBox(p.Key, 32) }

func (p PanelReality) context(port int) []byte {
	return fmt.Appendf(nil, "MCUI-XRAY-PANEL-REALITY-V1\n%d\n%s", port, p.PublicKey)
}

// NewPanelReality creates a fresh identity and seals its private key to the node.
func NewPanelReality(nodeKey string, port int, target string, names []string) (*PanelReality, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid REALITY inbound port")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	short := make([]byte, 8)
	if _, err := rand.Read(short); err != nil {
		return nil, err
	}
	p := &PanelReality{RealitySettings: RealitySettings{Target: target, ServerNames: append([]string(nil), names...),
		PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: hex.EncodeToString(short)}}
	p.Key, err = sealPanelSecret(nodeKey, p.context(port), key.Bytes())
	if err != nil {
		return nil, err
	}
	if !p.Valid() {
		return nil, errors.New("invalid REALITY target or server names")
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
	if err != nil || public != p.PublicKey {
		return "", errors.New("REALITY public key mismatch")
	}
	return encoded, nil
}
