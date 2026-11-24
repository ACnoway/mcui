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
}

// Configuration preserves the signed array format for existing inbound-only drafts.
type Configuration struct {
	Inbounds Plan     `json:"inbounds"`
	Network  *Network `json:"network"`
}

func (c Configuration) Valid() bool {
	if !c.Inbounds.Valid() {
		return false
	}
	if c.Network == nil {
		return true
	}
	n := c.Network
	if n.Outbounds == nil || n.Routes == nil || len(n.Outbounds) > maxOutbounds || len(n.Routes) > maxPorts*maxOutbounds {
		return false
	}
	ports := make(map[int]bool, len(c.Inbounds))
	for _, in := range c.Inbounds {
		ports[in.Port] = true
	}
	tags := make(map[string]bool, len(n.Outbounds))
	destinations := make(map[Destination]bool, len(n.Outbounds))
	for _, outbound := range n.Outbounds {
		if outbound.Tag == denyTag || !ValidUsername(outbound.Tag) || tags[outbound.Tag] ||
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
	if !plan.Valid() || !c.Allows(plan.Inbounds) {
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
	Protocol string            `json:"protocol"`
	Tag      string            `json:"tag"`
	Settings map[string]string `json:"settings,omitempty"`
}

type renderedRule struct {
	InboundTags []string `json:"inboundTag"`
	Network     string   `json:"network"`
	IP          []string `json:"ip"`
	Port        int      `json:"port"`
	OutboundTag string   `json:"outboundTag"`
}

func (n Network) render(inbounds []any, tags map[int]string, port int) ([]byte, Reference, error) {
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
	return encodeConfiguration(map[string]any{
		"log":      map[string]string{"loglevel": "none"},
		"inbounds": inbounds, "outbounds": outbounds,
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}, port)
}

// AppliedNetwork reconstructs the signed network draft from the committed config,
// independently of changes to the current node-local catalog.
func AppliedNetwork(data []byte, inboundPorts map[string]int) (*Network, error) {
	var config struct {
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
		config.Outbounds[1].Protocol == "freedom" && len(config.Outbounds[1].Settings) == 0 {
		return nil, nil
	}
	network := &Network{Outbounds: []Outbound{}, Routes: []Route{}}
	destinations := make(map[string]Destination, len(config.Outbounds)-1)
	for _, out := range config.Outbounds[1:] {
		endpoint, err := netip.ParseAddrPort(out.Settings["redirect"])
		destination := Destination{Address: endpoint.Addr().String(), Port: int(endpoint.Port())}
		if err != nil || out.Protocol != "freedom" || !destination.valid() {
			return nil, errors.New("invalid committed Xray outbound destination")
		}
		destinations[out.Tag] = destination
		network.Outbounds = append(network.Outbounds, Outbound{Tag: out.Tag, Destination: destination})
	}
	for _, rule := range config.Routing.Rules {
		destination, ok := destinations[rule.OutboundTag]
		if !ok || len(rule.InboundTags) != 1 || rule.Network != "tcp" || rule.Port != destination.Port ||
			!slices.Equal(rule.IP, []string{destination.Address + "/32"}) || inboundPorts[rule.InboundTags[0]] == 0 {
			return nil, errors.New("invalid committed Xray routing rule")
		}
		network.Routes = append(network.Routes, Route{InboundPort: inboundPorts[rule.InboundTags[0]], OutboundTag: rule.OutboundTag})
	}
	return network, nil
}
