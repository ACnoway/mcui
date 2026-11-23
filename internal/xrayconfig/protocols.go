package xrayconfig

import (
	"encoding/base64"
	"regexp"

	"github.com/ACnoway/mcui/internal/security"
)

const (
	HTTP              = "http"
	VLESS             = "vless"
	VLESSReality      = "vless-reality"
	VMess             = "vmess"
	Shadowsocks       = "shadowsocks"
	Trojan            = "trojan"
	shadowsocksMethod = "2022-blake3-aes-256-gcm"
)

var uuidV4 = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)

func UsesProtocolCredentials(protocol string) bool {
	return protocol == VLESS || protocol == VLESSReality || protocol == VMess || protocol == Shadowsocks || protocol == Trojan
}

func validShadowsocksKey(key string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(key)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == key
}

func validTypedCredential(protocol, value string) bool {
	switch protocol {
	case Shadowsocks:
		return validShadowsocksKey(value)
	case Trojan:
		return security.ValidNodeSecret(value)
	case VLESSReality:
		_, _, ok := splitRealityCredential(value)
		return ok
	default:
		return uuidV4.MatchString(value)
	}
}

func (c LocalCatalog) inboundSettings(protocol string, names []string) map[string]any {
	users := make([]map[string]string, 0, len(names))
	for _, name := range names {
		switch protocol {
		case VLESS, VMess:
			users = append(users, map[string]string{"email": name, "id": c.ProtocolCredentials[protocol][name]})
		case VLESSReality:
			id, _, _ := splitRealityCredential(c.ProtocolCredentials[protocol][name])
			users = append(users, map[string]string{"email": name, "id": id})
		case Shadowsocks, Trojan:
			users = append(users, map[string]string{"email": name, "password": c.ProtocolCredentials[protocol][name]})
		default:
			users = append(users, map[string]string{"user": name, "pass": c.Credentials[name]})
		}
	}
	settings := map[string]any{"users": users}
	switch protocol {
	case "socks":
		settings["auth"], settings["udp"] = "password", false
	case HTTP:
		settings["allowTransparent"] = false
	case VLESS, VLESSReality:
		settings["decryption"] = "none"
	case Shadowsocks:
		settings["method"], settings["password"], settings["network"] = shadowsocksMethod, c.ShadowsocksServerKey, "tcp"
	}
	return settings
}
