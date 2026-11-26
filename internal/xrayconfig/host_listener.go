package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/netip"
	"strings"
)

// HostListener is the actual host socket, independent of the advertised endpoint.
type HostListener struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (h HostListener) Valid() bool {
	ip, err := netip.ParseAddr(h.Address)
	return err == nil && ip.String() == h.Address && ip.Zone() == "" && !ip.Is4In6() &&
		!ip.IsMulticast() && !ip.IsLinkLocalUnicast() && h.Port >= 1 && h.Port <= 65535
}

const hostTagPrefix = "mcui-host-"

type hostTag struct {
	Port     int            `json:"port"`
	Endpoint PublicEndpoint `json:"endpoint,omitzero"`
}

// HostInboundTag binds the logical inbound and advertised endpoint into the
// generated configuration so the node can reconstruct the signed revision.
func HostInboundTag(port int, endpoint PublicEndpoint) string {
	data, _ := json.Marshal(hostTag{Port: port, Endpoint: endpoint})
	return hostTagPrefix + base64.RawURLEncoding.EncodeToString(data)
}

func ParseHostInboundTag(tag string) (int, PublicEndpoint, bool) {
	encoded, ok := strings.CutPrefix(tag, hostTagPrefix)
	if !ok || len(encoded) > 256 {
		return 0, PublicEndpoint{}, false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	var parsed hostTag
	if err != nil || jsonv2.Unmarshal(data, &parsed, jsonv2.RejectUnknownMembers(true)) != nil ||
		parsed.Port < 1024 || parsed.Port > 65535 || (parsed.Endpoint != (PublicEndpoint{}) && !parsed.Endpoint.Valid()) ||
		HostInboundTag(parsed.Port, parsed.Endpoint) != tag {
		return 0, PublicEndpoint{}, false
	}
	return parsed.Port, parsed.Endpoint, true
}
