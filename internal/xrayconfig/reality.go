package xrayconfig

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ACnoway/mcui/internal/security"
)

const (
	realityTargetPort = 10443
	realityServerName = "localhost"
)

var realityShortID = regexp.MustCompile(`^[0-9a-f]{16}$`)
var errRealityKey = errors.New("invalid node-local REALITY private key")

func RealityPublicKey(privateKey string) (string, error) {
	if !security.ValidNodeSecret(privateKey) {
		return "", errRealityKey
	}
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", errRealityKey
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", errRealityKey
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func splitRealityCredential(value string) (id, shortID string, valid bool) {
	id, shortID, found := strings.Cut(value, ":")
	return id, shortID, found && uuidV4.MatchString(id) && realityShortID.MatchString(shortID) && shortID != "0000000000000000"
}

func (c LocalCatalog) realityStreamSettings(names []string) map[string]any {
	ids := make([]string, 0, len(names))
	for _, name := range names {
		_, id, _ := splitRealityCredential(c.ProtocolCredentials[VLESSReality][name])
		ids = append(ids, id)
	}
	return map[string]any{
		"network": "raw", "security": "reality",
		"realitySettings": map[string]any{
			"target": fmt.Sprintf("127.0.0.1:%d", realityTargetPort), "serverNames": []string{realityServerName}, "privateKey": c.RealityPrivateKey,
			"shortIds": ids, "maxTimeDiff": 120000,
		},
	}
}
