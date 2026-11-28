package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ACnoway/mcui/internal/master/model"
	"github.com/ACnoway/mcui/pkg/proto"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func NewService(gdb *gorm.DB) *Service {
	return &Service{db: gdb}
}

type SubscriptionBundle struct {
	Client model.Client `json:"client"`
	Links  []string     `json:"links"`
	RawB64 string       `json:"rawBase64"`
}

func (s *Service) BuildBySubID(subID string) (*SubscriptionBundle, error) {
	var cl model.Client
	if err := s.db.Where("sub_id = ?", strings.TrimSpace(subID)).First(&cl).Error; err != nil {
		return nil, err
	}

	bundle := &SubscriptionBundle{Client: cl, Links: []string{}}
	now := time.Now().UnixMilli()
	if !cl.Enable || (cl.TotalBytes > 0 && cl.Up+cl.Down >= cl.TotalBytes) || (cl.ExpiryTime > 0 && now >= cl.ExpiryTime) {
		return bundle, nil
	}

	var links []model.ClientInbound
	if err := s.db.Where("client_id = ?", cl.ID).Order("inbound_id ASC").Find(&links).Error; err != nil {
		return nil, err
	}
	if len(links) == 0 {
		return bundle, nil
	}

	ibIDs := make([]uint, len(links))
	flowByInbound := make(map[uint]string, len(links))
	for i, lk := range links {
		ibIDs[i] = lk.InboundID
		flowByInbound[lk.InboundID] = lk.FlowOverride
	}

	var inbounds []model.Inbound
	if err := s.db.Where("id IN ? AND enable = ?", ibIDs, true).Order("id ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	if len(inbounds) == 0 {
		return bundle, nil
	}

	var nodes []model.Node
	_ = s.db.Where("enabled = ?", true).Find(&nodes).Error
	nodeMap := make(map[uint]model.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	for _, ib := range inbounds {
		node, ok := nodeMap[ib.NodeID]
		if !ok {
			continue
		}
		host := resolveNodeHost(node)
		if host == "" {
			continue
		}
		flow := cl.Flow
		if ov := flowByInbound[ib.ID]; ov != "" {
			flow = ov
		}
		remark := fmt.Sprintf("%s-%s", ib.Remark, cl.Email)
		if uri := buildShareLink(ib, cl, host, flow, remark); uri != "" {
			bundle.Links = append(bundle.Links, uri)
		}
	}

	joined := strings.Join(bundle.Links, "\n")
	bundle.RawB64 = base64.StdEncoding.EncodeToString([]byte(joined))
	return bundle, nil
}

func resolveNodeHost(n model.Node) string {
	if h := strings.TrimSpace(n.PublicHost); h != "" {
		return h
	}
	if h := strings.TrimSpace(n.PublicIPv4); h != "" {
		return h
	}
	if h := strings.TrimSpace(n.PublicIPv6); h != "" {
		return "[" + strings.Trim(h, "[]") + "]"
	}
	return ""
}

func buildShareLink(ib model.Inbound, cl model.Client, host, flow, remark string) string {
	var stream map[string]any
	_ = json.Unmarshal([]byte(ib.StreamSettings), &stream)
	var settings map[string]any
	_ = json.Unmarshal([]byte(ib.Settings), &settings)

	network := strField(stream, "network", "tcp")
	security := strField(stream, "security", "none")

	switch ib.Protocol {
	case proto.ProtocolVLESS:
		q := url.Values{}
		q.Set("type", network)
		q.Set("encryption", "none")
		q.Set("security", security)
		if flow != "" {
			q.Set("flow", flow)
		}
		applyStreamQuery(q, network, security, stream)
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
			url.PathEscape(cl.UUID), host, ib.Port, q.Encode(), url.PathEscape(remark))

	case proto.ProtocolTrojan:
		pwd := cl.Password
		if pwd == "" {
			pwd = cl.UUID
		}
		q := url.Values{}
		q.Set("type", network)
		q.Set("security", security)
		applyStreamQuery(q, network, security, stream)
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
			url.PathEscape(pwd), host, ib.Port, q.Encode(), url.PathEscape(remark))

	case proto.ProtocolVMess:
		vmessObj := map[string]any{
			"v":    "2",
			"ps":   remark,
			"add":  strings.Trim(host, "[]"),
			"port": fmt.Sprintf("%d", ib.Port),
			"id":   cl.UUID,
			"aid":  "0",
			"scy":  "auto",
			"net":  network,
			"type": "none",
			"tls":  "",
		}
		if security == "tls" {
			vmessObj["tls"] = "tls"
			if tlsMap, ok := stream["tlsSettings"].(map[string]any); ok {
				if sni := strField(tlsMap, "serverName", ""); sni != "" {
					vmessObj["sni"] = sni
				}
			}
		}
		if network == "ws" {
			if wsMap, ok := stream["wsSettings"].(map[string]any); ok {
				vmessObj["path"] = strField(wsMap, "path", "/")
				if headers, ok := wsMap["headers"].(map[string]any); ok {
					vmessObj["host"] = strField(headers, "Host", "")
				}
			}
		}
		raw, _ := json.Marshal(vmessObj)
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	case proto.ProtocolShadowsocks:
		method := strField(settings, "method", "chacha20-ietf-poly1305")
		pwd := cl.Password
		if pwd == "" {
			pwd = cl.UUID
		}
		cred := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pwd))
		return fmt.Sprintf("ss://%s@%s:%d#%s", cred, host, ib.Port, url.PathEscape(remark))
	}
	return ""
}

func applyStreamQuery(q url.Values, network, security string, stream map[string]any) {
	switch network {
	case "ws":
		if wsMap, ok := stream["wsSettings"].(map[string]any); ok {
			if p := strField(wsMap, "path", ""); p != "" {
				q.Set("path", p)
			}
			if h := strField(wsMap, "host", ""); h != "" {
				q.Set("host", h)
			} else if hdrs, ok := wsMap["headers"].(map[string]any); ok {
				if hh := strField(hdrs, "Host", ""); hh != "" {
					q.Set("host", hh)
				}
			}
		}
	case "grpc":
		if gMap, ok := stream["grpcSettings"].(map[string]any); ok {
			if sn := strField(gMap, "serviceName", ""); sn != "" {
				q.Set("serviceName", sn)
			}
		}
	case "xhttp":
		if xMap, ok := stream["xhttpSettings"].(map[string]any); ok {
			if p := strField(xMap, "path", ""); p != "" {
				q.Set("path", p)
			}
			if h := strField(xMap, "host", ""); h != "" {
				q.Set("host", h)
			}
			if m := strField(xMap, "mode", ""); m != "" {
				q.Set("mode", m)
			}
		}
	}

	switch security {
	case "tls":
		if tlsMap, ok := stream["tlsSettings"].(map[string]any); ok {
			if sni := strField(tlsMap, "serverName", ""); sni != "" {
				q.Set("sni", sni)
			}
			if fp := strField(tlsMap, "fingerprint", ""); fp != "" {
				q.Set("fp", fp)
			}
		}
	case "reality":
		if rMap, ok := stream["realitySettings"].(map[string]any); ok {
			if pbk := strField(rMap, "publicKey", ""); pbk != "" {
				q.Set("pbk", pbk)
			}
			if sni := strField(rMap, "serverName", ""); sni != "" {
				q.Set("sni", sni)
			} else if names, ok := rMap["serverNames"].([]any); ok && len(names) > 0 {
				if first, ok := names[0].(string); ok && first != "" {
					q.Set("sni", first)
				}
			}
			if sid := strField(rMap, "shortId", ""); sid != "" {
				q.Set("sid", sid)
			} else if sids, ok := rMap["shortIds"].([]any); ok && len(sids) > 0 {
				if first, ok := sids[0].(string); ok {
					q.Set("sid", first)
				}
			}
			fp := strField(rMap, "fingerprint", "chrome")
			q.Set("fp", fp)
			if spx := strField(rMap, "spiderX", ""); spx != "" {
				q.Set("spx", spx)
			}
		}
	}
}

func strField(m map[string]any, key, fallback string) string {
	if m == nil {
		return fallback
	}
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}
