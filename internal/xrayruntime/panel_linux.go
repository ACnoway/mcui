package xrayruntime

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"

	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const panelKeyFile = "panel-inbound-key.json"

// InitializePanelInbounds provisions the key for new nodes or nodes whose previous
// installation was explicitly uninstalled. The revision watermark is retained.
func (r *Runtime) InitializePanelInbounds() error {
	return r.initializePanelInbounds(inboundPolicyPath)
}

func (r *Runtime) initializePanelInbounds(policyPath string) error {
	if _, err := r.panelKey(); !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state, err := r.readStatus()
	if err != nil {
		return err
	}
	if state.Current != (selection{}) || state.Pending != nil ||
		(state.ConfigRevision != 0 && (state.LastAction != Uninstall || state.LastResult != "committed")) {
		return errors.New("uninstall Xray and finish lifecycle reconciliation before enabling panel inbounds")
	}
	for _, path := range []string{policyPath, filepath.Join(filepath.Dir(policyPath), catalogFilename)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("existing node-owned Xray policy requires migration")
		}
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return r.writeControl(panelKeyFile, []byte(`"`+base64.RawURLEncoding.EncodeToString(key.Bytes())+`"`))
}

func (r *Runtime) panelKey() (*ecdh.PrivateKey, error) {
	var encoded string
	if err := readJSON(filepath.Join(r.dir, "control", panelKeyFile), 0600, &encoded); err != nil {
		return nil, err
	}
	if !security.ValidNodeSecret(encoded) {
		return nil, errors.New("invalid Xray panel key")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(encoded)
	return ecdh.X25519().NewPrivateKey(raw)
}

func (r *Runtime) renderCandidate(path string, release Release, draft string) ([]byte, xrayconfig.Reference, bool, error) {
	key, err := r.panelKey()
	if errors.Is(err, os.ErrNotExist) {
		data, ref, err := readCandidate(path, release, draft)
		return data, ref, false, err
	}
	if err != nil {
		return nil, xrayconfig.Reference{}, false, err
	}
	if err := checkPolicyDirectory(path, release); err != nil {
		return nil, xrayconfig.Reference{}, true, err
	}
	plan, err := xrayconfig.ParseConfiguration(draft)
	if err != nil {
		return nil, xrayconfig.Reference{}, true, err
	}
	data, ref, err := plan.RenderPanel(key)
	return data, ref, true, err
}
