package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ACnoway/mcui/pkg/proto"
)

type FullConfig struct {
	Log       map[string]any   `json:"log"`
	API       map[string]any   `json:"api"`
	Stats     map[string]any   `json:"stats"`
	Policy    map[string]any   `json:"policy"`
	Inbounds  []map[string]any `json:"inbounds"`
	Outbounds []map[string]any `json:"outbounds"`
	Routing   map[string]any   `json:"routing"`
}

func RenderConfig(spec proto.DesiredCoreSpec, apiPort int) ([]byte, string, error) {
	inbounds := make([]map[string]any, 0, len(spec.Inbounds)+1)

	inbounds = append(inbounds, map[string]any{
		"tag":      "mcui-api",
		"listen":   "127.0.0.1",
		"port":     apiPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{
			"address": "127.0.0.1",
		},
	})

	for _, ib := range spec.Inbounds {
		entry, err := renderInbound(ib)
		if err != nil {
			return nil, "", fmt.Errorf("inbound %q: %w", ib.Tag, err)
		}
		inbounds = append(inbounds, entry)
	}

	cfg := FullConfig{
		Log: map[string]any{
			"loglevel": "warning",
		},
		API: map[string]any{
			"tag":      "mcui-api",
			"services": []string{"HandlerService", "StatsService"},
		},
		Stats: map[string]any{},
		Policy: map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
			"system": map[string]any{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		Inbounds: inbounds,
		Outbounds: []map[string]any{
			{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{},
			},
			{
				"tag":      "blocked",
				"protocol": "blackhole",
				"settings": map[string]any{},
			},
		},
		Routing: map[string]any{
			"domainStrategy": "AsIs",
			"rules": []map[string]any{
				{
					"type":        "field",
					"inboundTag":  []string{"mcui-api"},
					"outboundTag": "mcui-api",
				},
				{
					"type":        "field",
					"ip":          []string{"geoip:private"},
					"outboundTag": "blocked",
				},
			},
		},
	}

	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:16]), nil
}

func renderInbound(ib proto.InboundSpec) (map[string]any, error) {
	listen := ib.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}

	baseSettings := make(map[string]any)
	if len(ib.Settings) > 0 {
		if err := json.Unmarshal(ib.Settings, &baseSettings); err != nil {
			return nil, fmt.Errorf("invalid settings JSON: %w", err)
		}
	}

	clients := make([]map[string]any, 0, len(ib.Users))
	switch ib.Protocol {
	case proto.ProtocolVLESS:
		if _, ok := baseSettings["decryption"]; !ok {
			baseSettings["decryption"] = "none"
		}
		delete(baseSettings, "encryption")
		for _, u := range ib.Users {
			c := map[string]any{
				"id":    u.UUID,
				"email": u.Email,
				"level": 0,
			}
			if u.Flow != "" {
				c["flow"] = u.Flow
			}
			clients = append(clients, c)
		}
		baseSettings["clients"] = clients

	case proto.ProtocolVMess:
		for _, u := range ib.Users {
			clients = append(clients, map[string]any{
				"id":    u.UUID,
				"email": u.Email,
				"level": 0,
			})
		}
		baseSettings["clients"] = clients

	case proto.ProtocolTrojan:
		for _, u := range ib.Users {
			pwd := u.Password
			if pwd == "" {
				pwd = u.UUID
			}
			clients = append(clients, map[string]any{
				"password": pwd,
				"email":    u.Email,
				"level":    0,
			})
		}
		baseSettings["clients"] = clients

	case proto.ProtocolShadowsocks:
		method, _ := baseSettings["method"].(string)
		if method == "" {
			method = "chacha20-ietf-poly1305"
			baseSettings["method"] = method
		}
		if _, ok := baseSettings["network"]; !ok {
			baseSettings["network"] = "tcp,udp"
		}
		is2022 := len(method) >= 4 && method[:4] == "2022"
		for _, u := range ib.Users {
			pwd := u.Password
			if pwd == "" {
				pwd = u.UUID
			}
			c := map[string]any{
				"password": pwd,
				"email":    u.Email,
				"level":    0,
			}
			if !is2022 {
				c["method"] = method
			}
			clients = append(clients, c)
		}
		baseSettings["clients"] = clients

	default:
		return nil, fmt.Errorf("unsupported xray protocol %q", ib.Protocol)
	}

	out := map[string]any{
		"tag":      ib.Tag,
		"listen":   listen,
		"port":     ib.Port,
		"protocol": string(ib.Protocol),
		"settings": baseSettings,
	}

	if len(ib.StreamSettings) > 0 {
		var stream map[string]any
		if err := json.Unmarshal(ib.StreamSettings, &stream); err == nil && len(stream) > 0 {
			out["streamSettings"] = stream
		}
	}
	if len(ib.Sniffing) > 0 {
		var sniff map[string]any
		if err := json.Unmarshal(ib.Sniffing, &sniff); err == nil && len(sniff) > 0 {
			out["sniffing"] = sniff
		}
	} else {
		out["sniffing"] = map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls", "quic"},
		}
	}

	return out, nil
}
