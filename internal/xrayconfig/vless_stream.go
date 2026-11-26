package xrayconfig

import (
	"regexp"
	"strings"
)

// VLESSStream is the public part of a panel-managed VLESS transport.
// A nil value selects the existing RAW transport.
type VLESSStream struct {
	Network     string           `json:"network"`
	Security    string           `json:"security,omitempty"`
	Reality     *RealitySettings `json:"reality,omitempty"`
	Path        string           `json:"path,omitempty"`
	Host        string           `json:"host,omitempty"`
	ServiceName string           `json:"service_name,omitempty"`
	Authority   string           `json:"authority,omitempty"`
	MultiMode   bool             `json:"multi_mode,omitempty"`
	Mode        string           `json:"mode,omitempty"`
}

var vlessHost = regexp.MustCompile(`^[A-Za-z0-9.:-]{0,253}$`)
var vlessService = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,128}$`)

func (s *VLESSStream) Valid() bool {
	if s == nil {
		return true
	}
	if s.Security != "" && s.Security != "tls" && s.Security != "reality" {
		return false
	}
	if (s.Security == "reality" && (s.Reality == nil || !s.Reality.Valid())) || (s.Security != "reality" && s.Reality != nil) {
		return false
	}
	if !vlessHost.MatchString(s.Host) || !vlessHost.MatchString(s.Authority) || !vlessService.MatchString(s.ServiceName) ||
		len(s.Path) > 256 || strings.ContainsAny(s.Path, "\r\n\x00") {
		return false
	}
	switch s.Network {
	case "tcp":
		return (s.Security == "tls" || s.Security == "reality") && s.Path == "" && s.Host == "" && s.ServiceName == "" && s.Authority == "" && !s.MultiMode && s.Mode == ""
	case "ws", "httpupgrade":
		return s.Security != "reality" && strings.HasPrefix(s.Path, "/") && s.ServiceName == "" && s.Authority == "" && !s.MultiMode && s.Mode == ""
	case "xhttp":
		return strings.HasPrefix(s.Path, "/") && s.ServiceName == "" && s.Authority == "" && !s.MultiMode &&
			(s.Mode == "auto" || s.Mode == "packet-up" || s.Mode == "stream-up" || s.Mode == "stream-one")
	case "grpc":
		return s.Path == "" && s.Host == "" && s.Mode == ""
	default:
		return false
	}
}

func (s *VLESSStream) render() map[string]any {
	if s == nil {
		return nil
	}
	settings := map[string]any{}
	switch s.Network {
	case "tcp":
		return map[string]any{"network": "raw"}
	case "grpc":
		settings["serviceName"] = s.ServiceName
		settings["authority"] = s.Authority
		settings["multiMode"] = s.MultiMode
	default:
		settings["path"], settings["host"] = s.Path, s.Host
		if s.Network == "xhttp" {
			settings["mode"] = s.Mode
		}
	}
	return map[string]any{"network": s.Network, s.Network + "Settings": settings}
}
