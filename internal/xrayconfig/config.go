// Package xrayconfig defines the controlled Xray configuration templates.
package xrayconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"

	"github.com/ACnoway/mcui/internal/security"
)

const (
	Operation    = "config.apply"
	Version      = "v26.10.31"
	Architecture = "amd64"
	MaxSize      = 4096
	Username     = "mcui"
)

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Reference struct {
	Port   int    `json:"port"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

func (r Reference) Valid() bool {
	return r.Port >= 1024 && r.Port <= 65535 && r.Size > 0 && r.Size <= MaxSize && digest.MatchString(r.SHA256)
}

func (r Reference) Matches(data []byte) bool {
	sum := sha256.Sum256(data)
	return r.Valid() && len(data) == r.Size && hex.EncodeToString(sum[:]) == r.SHA256
}

type Policy struct {
	ReleaseSHA256   string `json:"release_sha256"`
	ListenPort      int    `json:"listen_port"`
	Password        string `json:"password"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
}

func (p *Policy) UnmarshalJSON(raw []byte) error {
	fields := map[string]any{
		"release_sha256":   &p.ReleaseSHA256,
		"listen_port":      &p.ListenPort,
		"password":         &p.Password,
		"destination_ip":   &p.DestinationIP,
		"destination_port": &p.DestinationPort,
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return errors.New("Xray inbound policy must be an object")
	}
	for decoder.More() {
		token, err := decoder.Token()
		key, _ := token.(string)
		value, ok := fields[key]
		if err != nil || !ok || decoder.Decode(value) != nil {
			return errors.New("invalid, duplicated, or unknown Xray inbound policy field")
		}
		delete(fields, key)
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') || len(fields) != 0 {
		return errors.New("incomplete Xray inbound policy")
	}
	return nil
}

var blocked = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(text string) bool {
	ip, err := netip.ParseAddr(text)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, prefix := range blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Render never incorporates arbitrary Xray configuration, paths, or rules.
func (p Policy) Render(releaseSHA256 string) ([]byte, Reference, error) {
	if !digest.MatchString(p.ReleaseSHA256) || p.ReleaseSHA256 != releaseSHA256 ||
		p.ListenPort < 1024 || p.ListenPort > 65535 || p.DestinationPort < 1 || p.DestinationPort > 65535 ||
		!publicIPv4(p.DestinationIP) || !security.ValidNodeSecret(p.Password) {
		return nil, Reference{}, errors.New("invalid node-local Xray inbound policy")
	}
	inbound := socksInbound(p.ListenPort, "inbound", []map[string]string{{"user": Username, "pass": p.Password}})
	return render([]any{inbound}, []string{"inbound"}, p.ListenPort, p.DestinationIP, p.DestinationPort)
}
