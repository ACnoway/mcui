package xrayconfig

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/netip"
	"slices"
	"strconv"
)

const maxOutbounds = 4
const MaxConfigurationSize = 3072

const denyTag = "deny"
const PanelDNSTag = "mcui-dns"
const PanelHostDNSTag = "mcui-host-dns"

// slirp4netns provides this DNS forwarder inside the node's Xray namespace.
const PanelDNSAddress = "10.0.2.3"

var panelDirectBlockedIPs = []string{
	"geoip:private", "0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
	// Xray normalizes IPv4-mapped addresses to IPv4 before matching. It rejects
	// ::ffff:0:0/96 as an IPv4 prefix with an invalid length.
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128",
	"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
}

func PanelDirectBlockedIPs() []string { return slices.Clone(panelDirectBlockedIPs) }

// Destination is a node-approved public IPv4 TCP endpoint.
type Destination struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

func (d Destination) valid() bool {
	return publicIPv4(d.Address) && d.Port > 0 && d.Port <= 65535
}

func (d Destination) String() string {
	return d.Address + ":" + strconv.Itoa(d.Port)
}

type Outbound struct {
	Tag         string      `json:"tag"`
	Destination Destination `json:"destination"`
}

type Route struct {
	InboundPort int    `json:"inbound_port"`
	OutboundTag string `json:"outbound_tag"`
}

type Network struct {
	Outbounds []Outbound `json:"outbounds"`
	Routes    []Route    `json:"routes"`
	Host      bool       `json:"host,omitempty"`
}

func (n Network) HasMultipleRoutes() bool {
	ports := make(map[int]bool, len(n.Routes))
	for _, route := range n.Routes {
		if ports[route.InboundPort] {
			return true
		}
		ports[route.InboundPort] = true
	}
	return false
}

// Configuration preserves the signed array format for existing inbound-only drafts.
type Configuration struct {
	Inbounds Plan                `json:"inbounds"`
	Network  *Network            `json:"network"`
	Panel    *PanelConfiguration `json:"panel,omitempty"`
}

func (c Configuration) Valid() bool {
	if !c.Inbounds.Valid() {
		return false
	}
	if c.Panel != nil && (c.Network == nil || !c.Panel.valid(c.Inbounds)) {
		return false
	}
	if c.Network == nil {
		for _, in := range c.Inbounds {
			if in.HostListen != nil {
				return false
			}
		}
		return true
	}
	n := c.Network
	if n.Outbounds == nil || n.Routes == nil || len(n.Outbounds) > maxOutbounds || len(n.Routes) > maxPorts*maxOutbounds {
		return false
	}
	ports := make(map[int]bool, len(c.Inbounds))
	for _, in := range c.Inbounds {
		if (in.HostListen != nil) != n.Host {
			return false
		}
		ports[in.Port] = true
	}
	tags := make(map[string]bool, len(n.Outbounds))
	destinations := make(map[Destination]bool, len(n.Outbounds))
	for _, outbound := range n.Outbounds {
		if outbound.Tag == denyTag || outbound.Tag == "direct" || outbound.Tag == PanelDNSTag || outbound.Tag == PanelHostDNSTag || !ValidUsername(outbound.Tag) || tags[outbound.Tag] ||
			!outbound.Destination.valid() || destinations[outbound.Destination] {
			return false
		}
		tags[outbound.Tag], destinations[outbound.Destination] = true, true
	}
	routes := make(map[Route]bool, len(n.Routes))
	for _, route := range n.Routes {
		if !ports[route.InboundPort] || !tags[route.OutboundTag] || routes[route] {
			return false
		}
		routes[route] = true
	}
	return true
}

func (c Configuration) Encode() string {
	if c.Network == nil {
		return c.Inbounds.Encode()
	}
	raw, _ := json.Marshal(c)
	return string(raw)
}

func ParseConfiguration(encoded string) (Configuration, error) {
	if len(encoded) > MaxConfigurationSize || encoded == "" {
		return Configuration{}, errors.New("invalid Xray configuration draft")
	}
	if encoded[0] == '[' {
		plan, err := ParsePlan(encoded)
		return Configuration{Inbounds: plan}, err
	}
	var c Configuration
	if jsonv2.Unmarshal([]byte(encoded), &c, jsonv2.RejectUnknownMembers(true)) != nil ||
		!c.Valid() || c.Encode() != encoded {
		return Configuration{}, errors.New("invalid Xray configuration draft")
	}
	return c, nil
}

func (c Catalog) AllowsConfiguration(plan Configuration) bool {
	if !plan.Valid() || plan.Panel != nil || (plan.Network != nil && plan.Network.Host) || !c.Allows(plan.Inbounds) {
		return false
	}
	if plan.Network == nil {
		return true
	}
	if len(c.RoutingDestinations) == 0 {
		return false
	}
	for _, outbound := range plan.Network.Outbounds {
		if !slices.Contains(c.RoutingDestinations, outbound.Destination) {
			return false
		}
	}
	return true
}

type renderedOutbound struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
	Settings any    `json:"settings,omitempty"`
}

type renderedRule struct {
	InboundTags []string `json:"inboundTag"`
	Network     string   `json:"network,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        int      `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

func (n Network) render(inbounds []any, tags map[int]string, port int, statistics bool, directTags []string) ([]byte, Reference, error) {
	if len(directTags) > 0 {
		outbounds := []renderedOutbound{{Protocol: "blackhole", Tag: denyTag}, {
			Protocol: "freedom", Tag: "direct",
			Settings: map[string]any{"domainStrategy": "UseIPv4", "finalRules": []any{map[string]any{
				"action": "block",
				"ip":     PanelDirectBlockedIPs(),
			}}},
		}, {Protocol: "freedom", Tag: PanelDNSTag}}
		destinations := make(map[string]Destination, len(n.Outbounds))
		for _, outbound := range n.Outbounds {
			destinations[outbound.Tag] = outbound.Destination
			outbounds = append(outbounds, renderedOutbound{
				Protocol: "freedom", Tag: outbound.Tag,
				Settings: map[string]string{"redirect": outbound.Destination.String()},
			})
		}
		rules := []renderedRule{}
		if n.Host {
			outbounds = slices.Delete(outbounds, 2, 3)
		} else {
			rules = append(rules, renderedRule{InboundTags: []string{PanelDNSTag}, Network: "udp", IP: []string{PanelDNSAddress + "/32"}, Port: 53, OutboundTag: PanelDNSTag})
		}
		for _, route := range n.Routes {
			destination := destinations[route.OutboundTag]
			rules = append(rules, renderedRule{
				InboundTags: []string{tags[route.InboundPort]}, Network: "tcp", IP: []string{destination.Address + "/32"},
				Port: destination.Port, OutboundTag: route.OutboundTag,
			})
		}
		rules = append(rules, renderedRule{InboundTags: slices.Clone(directTags), OutboundTag: "direct"})
		dns := map[string]any{"tag": PanelDNSTag, "servers": []string{PanelDNSAddress}, "queryStrategy": "UseIPv4"}
		if n.Host {
			dns = map[string]any{"tag": PanelHostDNSTag, "servers": []string{"localhost"}, "queryStrategy": "UseIPv4"}
		}
		config := map[string]any{
			"log": map[string]string{"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds,
			"dns": dns,
			"routing": map[string]any{
				"domainStrategy": "IPOnDemand",
				"rules":          rules,
			},
		}
		if statistics {
			enableStatistics(config)
		}
		return encodeConfiguration(config, port)
	}
	outbounds := []renderedOutbound{{Protocol: "blackhole", Tag: denyTag}}
	destinations := make(map[string]Destination, len(n.Outbounds))
	for _, outbound := range n.Outbounds {
		destinations[outbound.Tag] = outbound.Destination
		outbounds = append(outbounds, renderedOutbound{
			Protocol: "freedom", Tag: outbound.Tag,
			Settings: map[string]string{"redirect": outbound.Destination.String()},
		})
	}
	rules := make([]renderedRule, 0, len(n.Routes))
	for _, route := range n.Routes {
		destination := destinations[route.OutboundTag]
		rules = append(rules, renderedRule{
			InboundTags: []string{tags[route.InboundPort]}, Network: "tcp", IP: []string{destination.Address + "/32"},
			Port: destination.Port, OutboundTag: route.OutboundTag,
		})
	}
	config := map[string]any{
		"log":      map[string]string{"loglevel": "none"},
		"inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	if n.Host {
		config["dns"] = map[string]any{"tag": PanelHostDNSTag, "servers": []string{"localhost"}, "queryStrategy": "UseIPv4"}
	}
	if statistics {
		enableStatistics(config)
	}
	return encodeConfiguration(config, port)
}

// AppliedNetwork reconstructs the signed network draft from the committed config,
// independently of changes to the current node-local catalog.
func AppliedNetwork(data []byte, inboundPorts map[string]int) (*Network, error) {
	var config struct {
		DNS struct {
			Tag string `json:"tag"`
		} `json:"dns"`
		Outbounds []renderedOutbound `json:"outbounds"`
		Routing   struct {
			Rules []renderedRule `json:"rules"`
		} `json:"routing"`
	}
	if json.Unmarshal(data, &config) != nil || len(config.Outbounds) == 0 ||
		config.Outbounds[0].Tag != denyTag || config.Outbounds[0].Protocol != "blackhole" {
		return nil, errors.New("invalid committed Xray outbounds")
	}
	if len(config.Outbounds) == 2 && config.Outbounds[1].Tag == "allowed" &&
		config.Outbounds[1].Protocol == "freedom" && config.Outbounds[1].Settings == nil {
		return nil, nil
	}
	network := &Network{Outbounds: []Outbound{}, Routes: []Route{}, Host: config.DNS.Tag == PanelHostDNSTag}
	destinations := make(map[string]Destination, len(config.Outbounds)-1)
	for _, out := range config.Outbounds[1:] {
		if out.Tag == "direct" && out.Protocol == "freedom" {
			continue
		}
		if out.Tag == PanelDNSTag && out.Protocol == "freedom" && out.Settings == nil {
			continue
		}
		settings, ok := out.Settings.(map[string]any)
		redirect, valid := settings["redirect"].(string)
		if !ok || !valid {
			return nil, errors.New("invalid committed Xray outbound settings")
		}
		endpoint, err := netip.ParseAddrPort(redirect)
		destination := Destination{Address: endpoint.Addr().String(), Port: int(endpoint.Port())}
		if err != nil || out.Protocol != "freedom" || !destination.valid() {
			return nil, errors.New("invalid committed Xray outbound destination")
		}
		destinations[out.Tag] = destination
		network.Outbounds = append(network.Outbounds, Outbound{Tag: out.Tag, Destination: destination})
	}
	for _, rule := range config.Routing.Rules {
		if rule.OutboundTag == PanelDNSTag && slices.Equal(rule.InboundTags, []string{PanelDNSTag}) &&
			rule.Network == "udp" && slices.Equal(rule.IP, []string{PanelDNSAddress + "/32"}) && rule.Port == 53 {
			continue
		}
		if rule.OutboundTag == "direct" {
			if len(rule.InboundTags) == 0 || rule.Network != "" || len(rule.IP) != 0 || rule.Port != 0 {
				return nil, errors.New("invalid committed direct Xray route")
			}
			for _, tag := range rule.InboundTags {
				if inboundPorts[tag] == 0 {
					return nil, errors.New("invalid committed direct Xray inbound")
				}
			}
			continue
		}
		destination, ok := destinations[rule.OutboundTag]
		if !ok || len(rule.InboundTags) != 1 || rule.Network != "tcp" || rule.Port != destination.Port ||
			!slices.Equal(rule.IP, []string{destination.Address + "/32"}) || inboundPorts[rule.InboundTags[0]] == 0 {
			return nil, errors.New("invalid committed Xray routing rule")
		}
		network.Routes = append(network.Routes, Route{InboundPort: inboundPorts[rule.InboundTags[0]], OutboundTag: rule.OutboundTag})
	}
	return network, nil
}
