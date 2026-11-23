package xrayconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/ACnoway/mcui/internal/security"
)

const (
	maxPorts    = 4
	maxUsers    = 8
	maxGrants   = 16
	MaxPlanSize = 1024
)

var userID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,23}$`)

func ValidUsername(username string) bool {
	return userID.MatchString(username)
}

type Inbound struct {
	Port  int      `json:"port"`
	Users []string `json:"users"`
}

// Plan contains only listen ports and node-local credential names.
type Plan []Inbound

func (p Plan) Valid() bool {
	if p == nil || len(p) > maxPorts {
		return false
	}
	lastPort, grants := 1023, 0
	for _, in := range p {
		if in.Port <= lastPort || in.Port > 65535 || !validUsers(in.Users) {
			return false
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
	Ports []int    `json:"ports"`
	Users []string `json:"users"`
}

func (c Catalog) Valid() bool {
	if len(c.Ports) == 0 || len(c.Ports) > maxPorts || !validUsers(c.Users) {
		return false
	}
	last := 1023
	for _, port := range c.Ports {
		if port <= last || port > 65535 {
			return false
		}
		last = port
	}
	return true
}

func (c Catalog) Allows(p Plan) bool {
	if !p.Valid() {
		return false
	}
	for _, in := range p {
		if !slices.Contains(c.Ports, in.Port) {
			return false
		}
		for _, user := range in.Users {
			if !slices.Contains(c.Users, user) {
				return false
			}
		}
	}
	return true
}

type LocalCatalog struct {
	ReleaseSHA256   string            `json:"release_sha256"`
	Ports           []int             `json:"ports"`
	Credentials     map[string]string `json:"credentials"`
	DestinationIP   string            `json:"destination_ip"`
	DestinationPort int               `json:"destination_port"`
}

func (c *LocalCatalog) UnmarshalJSON(raw []byte) error {
	type document LocalCatalog
	return jsonv2.Unmarshal(raw, (*document)(c), jsonv2.RejectUnknownMembers(true))
}

func (c LocalCatalog) Public(releaseSHA256 string) (Catalog, error) {
	if !digest.MatchString(c.ReleaseSHA256) || c.ReleaseSHA256 != releaseSHA256 ||
		!publicIPv4(c.DestinationIP) || c.DestinationPort < 1 || c.DestinationPort > 65535 ||
		len(c.Credentials) > maxUsers || len(c.Ports) > maxPorts {
		return Catalog{}, errors.New("invalid node-local Xray catalog")
	}
	view := Catalog{Ports: slices.Clone(c.Ports)}
	slices.Sort(view.Ports)
	passwords := make(map[string]bool, len(c.Credentials))
	for user, password := range c.Credentials {
		if !security.ValidNodeSecret(password) || passwords[password] {
			return Catalog{}, errors.New("invalid or repeated node-local Xray credential")
		}
		passwords[password] = true
		view.Users = append(view.Users, user)
	}
	slices.Sort(view.Users)
	if !view.Valid() {
		return Catalog{}, errors.New("invalid node-local Xray catalog")
	}
	return view, nil
}

func (c LocalCatalog) Render(releaseSHA256 string, plan Plan) ([]byte, Reference, error) {
	view, err := c.Public(releaseSHA256)
	if err != nil || !view.Allows(plan) {
		return nil, Reference{}, errors.New("Xray inbound plan violates the node-local catalog")
	}
	inbounds := make([]any, 0, len(plan))
	tags := make([]string, 0, len(plan))
	port := view.Ports[0] // The signed reference requires a port even for a disabled configuration.
	for _, entry := range plan {
		tag := fmt.Sprintf("socks-%d", entry.Port)
		users := make([]map[string]string, 0, len(entry.Users))
		for _, user := range entry.Users {
			users = append(users, map[string]string{"user": user, "pass": c.Credentials[user]})
		}
		inbounds = append(inbounds, socksInbound(entry.Port, tag, users))
		tags = append(tags, tag)
	}
	if len(plan) != 0 {
		port = plan[0].Port
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
