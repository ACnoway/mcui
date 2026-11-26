package xrayconfig

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/ACnoway/mcui/internal/security"
)

// PanelConfiguration carries encrypted credentials in port and username order.
// A plan with one user per inbound retains its original wire encoding.
type PanelConfiguration struct {
	Credentials []string             `json:"credentials"`
	DirectPorts []int                `json:"direct_ports,omitempty"`
	TLS         *PanelTLS            `json:"tls,omitempty"`
	Reality     map[int]PanelReality `json:"reality,omitempty"`
	Statistics  bool                 `json:"statistics,omitempty"`
}

func (p PanelConfiguration) valid(plan Plan) bool {
	if p.Credentials == nil {
		return false
	}
	usesTLS := false
	realityCount := 0
	offset := 0
	lastDirectPort := 0
	for _, port := range p.DirectPorts {
		index := slices.IndexFunc(plan, func(inbound Inbound) bool { return inbound.Port == port })
		if port <= lastDirectPort || index < 0 || (plan[index].Protocol != "" && plan[index].Protocol != VLESS) {
			return false
		}
		lastDirectPort = port
	}
	for _, inbound := range plan {
		if !PanelProtocol(inbound.Protocol) || len(p.Credentials)-offset < len(inbound.Users) {
			return false
		}
		if inbound.Protocol == "" && !slices.Contains(p.DirectPorts, inbound.Port) {
			return false
		}
		if inbound.UsesTLS() {
			usesTLS = true
			if p.TLS == nil || p.TLS.Trust.SHA256 != inbound.TLSCertSHA256 {
				return false
			}
		}
		if inbound.Protocol == VLESS && inbound.VLESSStream != nil && inbound.VLESSStream.Security == "reality" {
			identity, ok := p.Reality[inbound.Port]
			if !ok || !identity.Valid() || !reflect.DeepEqual(identity.RealitySettings, *inbound.VLESSStream.Reality) {
				return false
			}
			realityCount++
		}
		length := 43
		if inbound.Protocol == VLESS || inbound.Protocol == VMess {
			length = 36
		}
		for _, box := range p.Credentials[offset : offset+len(inbound.Users)] {
			if !validPanelBox(box, length) {
				return false
			}
		}
		offset += len(inbound.Users)
	}
	return offset == len(p.Credentials) && len(p.Reality) == realityCount && usesTLS == (p.TLS != nil) && (!usesTLS || p.TLS.valid())
}

func PanelProtocol(protocol string) bool {
	return protocol == "" || protocol == HTTP || protocol == VLESS || protocol == VMess || protocol == Trojan
}

func validPanelBox(sealed string, length int) bool {
	box, err := base64.RawURLEncoding.Strict().DecodeString(sealed)
	return err == nil && len(box) == 32+16+length && base64.RawURLEncoding.EncodeToString(box) == sealed
}

func credentialContext(inbound Inbound, user string) []byte {
	return fmt.Appendf(nil, "MCUI-XRAY-PANEL-CREDENTIAL-V1\n%d\n%s\n%s", inbound.Port, inbound.Protocol, user)
}

func validPanelCredential(inbound Inbound, credential string) bool {
	if inbound.Protocol == "" || inbound.Protocol == HTTP {
		return security.ValidNodeSecret(credential)
	}
	return validTypedCredential(inbound.Protocol, credential)
}

// SealPanelCredential encrypts the credential to the Helper's enrollment key.
func SealPanelCredential(public string, inbound Inbound, credential string) (string, error) {
	// A credential is bound to a single user; flow authorization is signed separately.
	inbound.VLESSFlows = nil
	if !(Plan{inbound}).Valid() || !PanelProtocol(inbound.Protocol) || len(inbound.Users) != 1 ||
		!validPanelCredential(inbound, credential) {
		return "", errors.New("invalid panel Xray credential")
	}
	return sealPanelSecret(public, credentialContext(inbound, inbound.Users[0]), []byte(credential))
}

// PanelCredentialIndex locates a credential by its inbound and username.
func (c Configuration) PanelCredentialIndex(port int, username string) int {
	if c.Panel == nil {
		return -1
	}
	offset := 0
	for _, inbound := range c.Inbounds {
		for _, user := range inbound.Users {
			if inbound.Port == port && user == username {
				return offset
			}
			offset++
		}
	}
	return -1
}

func sealPanelSecret(public string, info, secret []byte) (string, error) {
	if !security.ValidNodeSecret(public) {
		return "", errors.New("invalid panel Xray node key")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(public)
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return "", err
	}
	pub, err := hpke.NewDHKEMPublicKey(key)
	if err != nil {
		return "", err
	}
	sealed, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.AES128GCM(), info, secret)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func openPanelSecret(private hpke.PrivateKey, info []byte, ciphertext string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return hpke.Open(private, hpke.HKDFSHA256(), hpke.AES128GCM(), info, sealed)
}

func (c Configuration) RenderPanel(key *ecdh.PrivateKey) ([]byte, Reference, error) {
	if key == nil || c.Panel == nil || !c.Valid() {
		return nil, Reference{}, errors.New("invalid panel Xray configuration")
	}
	private, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, Reference{}, err
	}
	var tls *TrojanTLS
	if c.Panel.TLS != nil {
		tls, err = c.Panel.TLS.open(private)
		if err != nil {
			return nil, Reference{}, err
		}
	}
	inbounds := make([]any, 0, len(c.Inbounds))
	tags := make(map[int]string, len(c.Inbounds))
	port := 1080 // A disabled revision still carries a valid signed reference.
	if len(c.Inbounds) != 0 {
		port = c.Inbounds[0].Port
	}
	offset := 0
	for _, inbound := range c.Inbounds {
		protocol := inbound.Protocol
		if protocol == "" {
			protocol = "socks"
		}
		credentials := make(map[string]string, len(inbound.Users))
		for _, user := range inbound.Users {
			secret, err := openPanelSecret(private, credentialContext(inbound, user), c.Panel.Credentials[offset])
			if err != nil || !validPanelCredential(inbound, string(secret)) {
				return nil, Reference{}, errors.New("panel Xray credential cannot be opened")
			}
			if UsesProtocolCredentials(protocol) {
				for _, existing := range credentials {
					if existing == string(secret) {
						return nil, Reference{}, errors.New("duplicate panel Xray credential")
					}
				}
			}
			credentials[user] = string(secret)
			offset++
		}
		catalog := LocalCatalog{
			Credentials:         credentials,
			ProtocolCredentials: map[string]map[string]string{protocol: credentials},
		}
		tag := fmt.Sprintf("%s-%d", protocol, inbound.Port)
		listen := "127.0.0.1"
		listenPort := inbound.Port
		if c.Network != nil && c.Network.Host {
			listen, listenPort = inbound.HostListen.Address, inbound.HostListen.Port
			tag = HostInboundTag(inbound.Port, inbound.PublicEndpoint)
		} else if inbound.PublicEndpoint != (PublicEndpoint{}) {
			listen, tag = PublicListenAddress, publicTagPrefix+inbound.PublicEndpoint.String()
		}
		settings := catalog.inboundSettings(protocol, inbound.Users)
		if protocol == VLESS {
			for _, user := range settings["users"].([]map[string]string) {
				if flow := inbound.VLESSFlows[user["email"]]; flow != "" {
					user["flow"] = flow
				}
			}
		}
		entry := map[string]any{
			"listen": listen, "port": listenPort, "protocol": protocol, "tag": tag,
			"settings": settings,
		}
		if protocol == Trojan {
			entry["streamSettings"] = tls.streamSettings()
		} else if inbound.VLESSStream != nil {
			stream := inbound.VLESSStream.render()
			if inbound.UsesTLS() {
				tlsStream := tls.streamSettings()
				stream["security"], stream["tlsSettings"] = tlsStream["security"], tlsStream["tlsSettings"]
			} else if inbound.VLESSStream.Security == "reality" {
				identity := c.Panel.Reality[inbound.Port]
				privateKey, err := identity.open(private, inbound.Port)
				if err != nil {
					return nil, Reference{}, err
				}
				stream["security"] = "reality"
				stream["realitySettings"] = map[string]any{"target": identity.Target, "serverNames": identity.ServerNames,
					"privateKey": privateKey, "shortIds": []string{identity.ShortID}}
			}
			entry["streamSettings"] = stream
		}
		inbounds = append(inbounds, entry)
		tags[inbound.Port] = tag
	}
	directTags := make([]string, 0, len(c.Panel.DirectPorts))
	for _, directPort := range c.Panel.DirectPorts {
		directTags = append(directTags, tags[directPort])
	}
	return c.Network.render(inbounds, tags, port, c.Panel.Statistics, directTags)
}
