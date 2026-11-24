package xrayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/ACnoway/mcui/internal/security"
)

const (
	maxPorts    = 4
	maxUsers    = 8
	maxGrants   = 16
	MaxPlanSize = 1536
)

var userID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,23}$`)

func ValidUsername(username string) bool {
	return userID.MatchString(username)
}

type Inbound struct {
	Port             int            `json:"port"`
	Protocol         string         `json:"protocol,omitempty"` // Empty preserves the original SOCKS template.
	TLSCertSHA256    string         `json:"tls_cert_sha256,omitempty"`
	RealityPublicKey string         `json:"reality_public_key,omitempty"`
	PublicEndpoint   PublicEndpoint `json:"public_endpoint,omitzero"`
	Users            []string       `json:"users"`
}

// Plan contains only listen ports, approved protocols and node-local credential names.
type Plan []Inbound

func (p Plan) Valid() bool {
	if p == nil || len(p) > maxPorts {
		return false
	}
	lastPort, grants := 1023, 0
	publicEndpoints := make(map[PublicEndpoint]bool)
	for _, in := range p {
		if in.Port <= lastPort || in.Port > 65535 || !validUsers(in.Users) ||
			(in.Protocol != "" && in.Protocol != HTTP && !UsesProtocolCredentials(in.Protocol)) ||
			(in.Protocol == Trojan && !digest.MatchString(in.TLSCertSHA256)) || (in.Protocol != Trojan && in.TLSCertSHA256 != "") ||
			(in.Protocol == VLESSReality && !security.ValidNodeSecret(in.RealityPublicKey)) || (in.Protocol != VLESSReality && in.RealityPublicKey != "") {
			return false
		}
		if in.PublicEndpoint != (PublicEndpoint{}) {
			if !Publishable(in.Protocol) || !in.PublicEndpoint.Valid() || publicEndpoints[in.PublicEndpoint] {
				return false
			}
			publicEndpoints[in.PublicEndpoint] = true
		}
		grants += len(in.Users)
		lastPort = in.Port
	}
	return grants <= maxGrants
}

func validUsers(users []string) bool {
	if len(users) == 0 || len(users) > maxUsers {
		return false
	}
	last := ""
	for _, user := range users {
		if user <= last || !ValidUsername(user) {
			return false
		}
		last = user
	}
	return true
}

func (p Plan) Encode() string {
	raw, _ := json.Marshal(p)
	return string(raw)
}

func PlanDigest(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return hex.EncodeToString(sum[:])
}

func ValidPlanDigest(text string) bool {
	return digest.MatchString(text)
}

func ParsePlan(encoded string) (Plan, error) {
	var p Plan
	if len(encoded) > MaxPlanSize || jsonv2.Unmarshal([]byte(encoded), &p, jsonv2.RejectUnknownMembers(true)) != nil ||
		!p.Valid() || p.Encode() != encoded {
		return nil, errors.New("invalid Xray inbound plan")
	}
	return p, nil
}

type Catalog struct {
	Ports               []int                  `json:"ports"`
	Users               []string               `json:"users"`
	HTTPPorts           []int                  `json:"http_ports,omitempty"`
	PortProtocols       map[int]string         `json:"port_protocols,omitempty"`
	ProtocolUsers       map[string][]string    `json:"protocol_users,omitempty"`
	TrojanTrust         *TrojanTrust           `json:"trojan_trust,omitempty"`
	RealityPublicKey    string                 `json:"reality_public_key,omitempty"`
	PublicEndpoints     map[int]PublicEndpoint `json:"public_endpoints,omitempty"`
	RoutingDestinations []Destination          `json:"routing_destinations,omitempty"`
}

func (c Catalog) Valid() bool {
	if len(c.Ports) == 0 || len(c.Ports) > maxPorts || len(c.HTTPPorts)+len(c.PortProtocols) > len(c.Ports) ||
		(len(c.Users) > 0 && !validUsers(c.Users)) {
		return false
	}
	if len(c.RoutingDestinations) > maxOutbounds {
		return false
	}
	destinations := make(map[Destination]bool, len(c.RoutingDestinations))
	for _, destination := range c.RoutingDestinations {
		if !destination.valid() || destinations[destination] {
			return false
		}
		destinations[destination] = true
	}
	last := 1023
	for _, port := range c.Ports {
		if port <= last || port > 65535 {
			return false
		}
		last = port
	}
	last = 1023
	for _, port := range c.HTTPPorts {
		if port <= last || !slices.Contains(c.Ports, port) {
			return false
		}
		last = port
	}
	needsTrojan, needsReality := false, false
	for port, protocol := range c.PortProtocols {
		if !UsesProtocolCredentials(protocol) || !slices.Contains(c.Ports, port) || slices.Contains(c.HTTPPorts, port) {
			return false
		}
		needsTrojan = needsTrojan || protocol == Trojan
		needsReality = needsReality || protocol == VLESSReality
	}
	if needsTrojan != (c.TrojanTrust != nil) || (c.TrojanTrust != nil && !c.TrojanTrust.Valid()) {
		return false
	}
	if needsReality {
		if !security.ValidNodeSecret(c.RealityPublicKey) || slices.Contains(c.Ports, realityTargetPort) {
			return false
		}
	} else if c.RealityPublicKey != "" {
		return false
	}
	if len(c.PublicEndpoints) > len(c.PortProtocols) {
		return false
	}
	endpoints := make(map[PublicEndpoint]bool)
	for port, endpoint := range c.PublicEndpoints {
		if !Publishable(c.PortProtocols[port]) || !endpoint.Valid() || endpoints[endpoint] {
			return false
		}
		endpoints[endpoint] = true
	}
	names := make(map[string]bool)
	for _, user := range c.Users {
		names[user] = true
	}
	for protocol, users := range c.ProtocolUsers {
		if !UsesProtocolCredentials(protocol) || !validUsers(users) {
			return false
		}
		for _, user := range users {
			names[user] = true
		}
	}
	return len(names) > 0 && len(names) <= maxUsers
}

func (c Catalog) Allows(p Plan) bool {
	if !p.Valid() {
		return false
	}
	for _, in := range p {
		approved, users, ok := c.Inbound(in.Port)
		if !ok || in.Protocol != approved.Protocol || in.PublicEndpoint != approved.PublicEndpoint ||
			in.TLSCertSHA256 != approved.TLSCertSHA256 || in.RealityPublicKey != approved.RealityPublicKey {
			return false
		}
		for _, user := range in.Users {
			if !slices.Contains(users, user) {
				return false
			}
		}
	}
	return true
}

// Inbound returns a node-approved template and the local credential names for it.
func (c Catalog) Inbound(port int) (Inbound, []string, bool) {
	if !slices.Contains(c.Ports, port) {
		return Inbound{}, nil, false
	}
	in := Inbound{Port: port, Protocol: c.PortProtocols[port], PublicEndpoint: c.PublicEndpoints[port]}
	if slices.Contains(c.HTTPPorts, port) {
		in.Protocol = HTTP
	}
	if in.Protocol == Trojan && c.TrojanTrust != nil {
		in.TLSCertSHA256 = c.TrojanTrust.SHA256
	}
	if in.Protocol == VLESSReality {
		in.RealityPublicKey = c.RealityPublicKey
	}
	users := c.Users
	if UsesProtocolCredentials(in.Protocol) {
		users = c.ProtocolUsers[in.Protocol]
	}
	return in, users, true
}

type LocalCatalog struct {
	ReleaseSHA256        string                       `json:"release_sha256"`
	Ports                []int                        `json:"ports"`
	Credentials          map[string]string            `json:"credentials"`
	DestinationIP        string                       `json:"destination_ip"`
	DestinationPort      int                          `json:"destination_port"`
	HTTPPorts            []int                        `json:"http_ports,omitempty"`
	PortProtocols        map[int]string               `json:"port_protocols,omitempty"`
	ProtocolCredentials  map[string]map[string]string `json:"protocol_credentials,omitempty"`
	ShadowsocksServerKey string                       `json:"shadowsocks_server_key,omitempty"`
	TrojanTLS            *TrojanTLS                   `json:"trojan_tls,omitempty"`
	RealityPrivateKey    string                       `json:"reality_private_key,omitempty"`
	PublicEndpoints      map[int]PublicEndpoint       `json:"public_endpoints,omitempty"`
	RoutingDestinations  []Destination                `json:"routing_destinations,omitempty"`
}

func (c *LocalCatalog) UnmarshalJSON(raw []byte) error {
	type document LocalCatalog
	return jsonv2.Unmarshal(raw, (*document)(c), jsonv2.RejectUnknownMembers(true))
}

func (c LocalCatalog) Public(releaseSHA256 string) (Catalog, error) {
	if !digest.MatchString(c.ReleaseSHA256) || c.ReleaseSHA256 != releaseSHA256 ||
		!publicIPv4(c.DestinationIP) || c.DestinationPort < 1 || c.DestinationPort > 65535 ||
		len(c.Credentials) > maxUsers || len(c.Ports) > maxPorts || len(c.HTTPPorts)+len(c.PortProtocols) > len(c.Ports) ||
		len(c.PublicEndpoints) > len(c.PortProtocols) {
		return Catalog{}, errors.New("invalid node-local Xray catalog")
	}
	view := Catalog{
		Ports: slices.Clone(c.Ports), HTTPPorts: slices.Clone(c.HTTPPorts),
		PortProtocols: maps.Clone(c.PortProtocols), PublicEndpoints: maps.Clone(c.PublicEndpoints),
		RoutingDestinations: slices.Clone(c.RoutingDestinations),
	}
	slices.Sort(view.Ports)
	slices.Sort(view.HTTPPorts)
	passwords := make(map[string]bool, len(c.Credentials))
	for user, password := range c.Credentials {
		if !security.ValidNodeSecret(password) || passwords[password] {
			return Catalog{}, errors.New("invalid or repeated node-local Xray credential")
		}
		passwords[password] = true
		view.Users = append(view.Users, user)
	}
	slices.Sort(view.Users)
	needsShadowsocksKey := c.ShadowsocksServerKey != "" || len(c.ProtocolCredentials[Shadowsocks]) > 0
	needsTrojan, needsReality := false, false
	for _, protocol := range c.PortProtocols {
		needsShadowsocksKey = needsShadowsocksKey || protocol == Shadowsocks
		needsTrojan = needsTrojan || protocol == Trojan
		needsReality = needsReality || protocol == VLESSReality
	}
	if needsTrojan {
		trust, err := c.TrojanTLS.trust()
		if err != nil {
			return Catalog{}, err
		}
		view.TrojanTrust = trust
	}
	if needsReality {
		publicKey, err := RealityPublicKey(c.RealityPrivateKey)
		if err != nil {
			return Catalog{}, err
		}
		if passwords[c.RealityPrivateKey] {
			return Catalog{}, errors.New("repeated node-local Xray credential")
		}
		passwords[c.RealityPrivateKey] = true
		view.RealityPublicKey = publicKey
	}
	if needsShadowsocksKey {
		if !validShadowsocksKey(c.ShadowsocksServerKey) {
			return Catalog{}, errors.New("invalid node-local Shadowsocks server key")
		}
		passwords[c.ShadowsocksServerKey] = true
	}
	if len(c.ProtocolCredentials) > 0 {
		view.ProtocolUsers = make(map[string][]string, len(c.ProtocolCredentials))
	}
	shortIDs := make(map[string]bool)
	for protocol, credentials := range c.ProtocolCredentials {
		if !UsesProtocolCredentials(protocol) || len(credentials) == 0 || len(credentials) > maxUsers {
			return Catalog{}, errors.New("invalid node-local Xray protocol credentials")
		}
		names := make([]string, 0, len(credentials))
		for name, secret := range credentials {
			if !validTypedCredential(protocol, secret) {
				return Catalog{}, errors.New("invalid or repeated node-local Xray credential")
			}
			identity := secret
			if protocol == VLESSReality {
				id, shortID, _ := splitRealityCredential(secret)
				if shortIDs[shortID] {
					return Catalog{}, errors.New("repeated node-local REALITY short ID")
				}
				shortIDs[shortID] = true
				identity = id
			}
			if passwords[identity] {
				return Catalog{}, errors.New("invalid or repeated node-local Xray credential")
			}
			passwords[identity] = true
			names = append(names, name)
		}
		slices.Sort(names)
		view.ProtocolUsers[protocol] = names
	}
	if !view.Valid() {
		return Catalog{}, errors.New("invalid node-local Xray catalog")
	}
	return view, nil
}

func (c LocalCatalog) Render(releaseSHA256 string, plan Plan) ([]byte, Reference, error) {
	return c.RenderConfiguration(releaseSHA256, Configuration{Inbounds: plan})
}

func (c LocalCatalog) RenderConfiguration(releaseSHA256 string, draft Configuration) ([]byte, Reference, error) {
	view, err := c.Public(releaseSHA256)
	if err != nil || !view.AllowsConfiguration(draft) {
		return nil, Reference{}, errors.New("Xray configuration draft violates the node-local catalog")
	}
	plan := draft.Inbounds
	inbounds := make([]any, 0, len(plan))
	tags := make([]string, 0, len(plan))
	inboundTags := make(map[int]string, len(plan))
	port := view.Ports[0] // The signed reference requires a port even for a disabled configuration.
	for _, entry := range plan {
		protocol := entry.Protocol
		if protocol == "" {
			protocol = "socks"
		}
		tag := fmt.Sprintf("%s-%d", protocol, entry.Port)
		listen := "127.0.0.1"
		if entry.PublicEndpoint != (PublicEndpoint{}) {
			listen, tag = PublicListenAddress, publicTagPrefix+entry.PublicEndpoint.String()
		}
		inbound := map[string]any{
			"listen": listen, "port": entry.Port, "protocol": protocol, "tag": tag,
			"settings": c.inboundSettings(protocol, entry.Users),
		}
		if protocol == Trojan {
			inbound["streamSettings"] = c.TrojanTLS.streamSettings()
		} else if protocol == VLESSReality {
			inbound["protocol"] = VLESS
			inbound["streamSettings"] = c.realityStreamSettings(entry.Users)
		}
		inbounds = append(inbounds, inbound)
		tags = append(tags, tag)
		inboundTags[entry.Port] = tag
	}
	if len(plan) != 0 {
		port = plan[0].Port
	}
	if draft.Network != nil {
		return draft.Network.render(inbounds, inboundTags, port)
	}
	return render(inbounds, tags, port, c.DestinationIP, c.DestinationPort)
}

func render(inbounds []any, tags []string, port int, destinationIP string, destinationPort int) ([]byte, Reference, error) {
	config := map[string]any{
		"log":      map[string]string{"loglevel": "none"},
		"inbounds": inbounds,
		"outbounds": []map[string]string{
			{"protocol": "blackhole", "tag": "deny"},
			{"protocol": "freedom", "tag": "allowed"},
		},
	}
	if len(tags) > 0 {
		config["routing"] = map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"inboundTag": tags, "network": "tcp", "ip": []string{destinationIP + "/32"},
				"port": destinationPort, "outboundTag": "allowed",
			}},
		}
	}
	return encodeConfiguration(config, port)
}

func encodeConfiguration(config map[string]any, port int) ([]byte, Reference, error) {
	data, err := json.Marshal(config)
	if err != nil || len(data) > MaxSize {
		return nil, Reference{}, errors.New("invalid or oversized Xray configuration")
	}
	sum := sha256.Sum256(data)
	return data, Reference{Port: port, Size: len(data), SHA256: hex.EncodeToString(sum[:])}, nil
}

func socksInbound(port int, tag string, users []map[string]string) map[string]any {
	return map[string]any{
		"listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": tag,
		"settings": map[string]any{"auth": "password", "udp": false, "users": users},
	}
}
