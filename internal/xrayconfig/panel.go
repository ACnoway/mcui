package xrayconfig

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ACnoway/mcui/internal/security"
)

// PanelConfiguration carries encrypted credentials in port and username order.
// A plan with one user per inbound retains its original wire encoding.
type PanelConfiguration struct {
	Credentials []string  `json:"credentials"`
	TLS         *PanelTLS `json:"tls,omitempty"`
}

func (p PanelConfiguration) valid(plan Plan, routes []Route) bool {
	if p.Credentials == nil {
		return false
	}
	usesTLS := false
	offset := 0
	for _, inbound := range plan {
		if !PanelProtocol(inbound.Protocol) || len(p.Credentials)-offset < len(inbound.Users) {
			return false
		}
		if inbound.Protocol == Trojan {
			usesTLS = true
			if p.TLS == nil || p.TLS.Trust.SHA256 != inbound.TLSCertSHA256 {
				return false
			}
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
	if offset != len(p.Credentials) || usesTLS != (p.TLS != nil) || (usesTLS && !p.TLS.valid()) {
		return false
	}
	ports := make(map[int]bool, len(routes))
	for _, route := range routes {
		if ports[route.InboundPort] {
			return false
		}
		ports[route.InboundPort] = true
	}
	return true
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
		if inbound.PublicEndpoint != (PublicEndpoint{}) {
			listen, tag = PublicListenAddress, publicTagPrefix+inbound.PublicEndpoint.String()
		}
		entry := map[string]any{
			"listen": listen, "port": inbound.Port, "protocol": protocol, "tag": tag,
			"settings": catalog.inboundSettings(protocol, inbound.Users),
		}
		if protocol == Trojan {
			entry["streamSettings"] = tls.streamSettings()
		}
		inbounds = append(inbounds, entry)
		tags[inbound.Port] = tag
	}
	return c.Network.render(inbounds, tags, port)
}
