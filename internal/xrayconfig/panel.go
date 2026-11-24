package xrayconfig

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ACnoway/mcui/internal/security"
)

// PanelConfiguration carries one encrypted credential for each inbound, in
// port order. The signed plan binds the ciphertext to its node and release.
type PanelConfiguration struct {
	Credentials []string `json:"credentials"`
}

func (p PanelConfiguration) valid(plan Plan, routes []Route) bool {
	if p.Credentials == nil || len(p.Credentials) != len(plan) {
		return false
	}
	for index, inbound := range plan {
		if !PanelProtocol(inbound.Protocol) || len(inbound.Users) != 1 || inbound.PublicEndpoint != (PublicEndpoint{}) {
			return false
		}
		box, err := base64.RawURLEncoding.Strict().DecodeString(p.Credentials[index])
		length := 43
		if inbound.Protocol == VLESS || inbound.Protocol == VMess {
			length = 36
		}
		if err != nil || len(box) != 32+16+length || base64.RawURLEncoding.EncodeToString(box) != p.Credentials[index] {
			return false
		}
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
	return protocol == "" || protocol == HTTP || protocol == VLESS || protocol == VMess
}

func credentialContext(inbound Inbound) []byte {
	return fmt.Appendf(nil, "MCUI-XRAY-PANEL-CREDENTIAL-V1\n%d\n%s\n%s", inbound.Port, inbound.Protocol, inbound.Users[0])
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
		!validPanelCredential(inbound, credential) || !security.ValidNodeSecret(public) {
		return "", errors.New("invalid panel Xray credential")
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
	sealed, err := hpke.Seal(pub, hpke.HKDFSHA256(), hpke.AES128GCM(), credentialContext(inbound), []byte(credential))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c Configuration) RenderPanel(key *ecdh.PrivateKey) ([]byte, Reference, error) {
	if key == nil || c.Panel == nil || !c.Valid() {
		return nil, Reference{}, errors.New("invalid panel Xray configuration")
	}
	private, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, Reference{}, err
	}
	inbounds := make([]any, 0, len(c.Inbounds))
	tags := make(map[int]string, len(c.Inbounds))
	port := 1080 // A disabled revision still carries a valid signed reference.
	if len(c.Inbounds) != 0 {
		port = c.Inbounds[0].Port
	}
	for index, inbound := range c.Inbounds {
		sealed, _ := base64.RawURLEncoding.DecodeString(c.Panel.Credentials[index])
		secret, err := hpke.Open(private, hpke.HKDFSHA256(), hpke.AES128GCM(), credentialContext(inbound), sealed)
		if err != nil || !validPanelCredential(inbound, string(secret)) {
			return nil, Reference{}, errors.New("panel Xray credential cannot be opened")
		}
		protocol := inbound.Protocol
		if protocol == "" {
			protocol = "socks"
		}
		user := inbound.Users[0]
		catalog := LocalCatalog{
			Credentials:         map[string]string{user: string(secret)},
			ProtocolCredentials: map[string]map[string]string{protocol: {user: string(secret)}},
		}
		tag := fmt.Sprintf("%s-%d", protocol, inbound.Port)
		inbounds = append(inbounds, map[string]any{
			"listen": "127.0.0.1", "port": inbound.Port, "protocol": protocol, "tag": tag,
			"settings": catalog.inboundSettings(protocol, inbound.Users),
		})
		tags[inbound.Port] = tag
	}
	return c.Network.render(inbounds, tags, port)
}
