package master

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/security"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

const xrayCredentialDeliveryLifetime = 24 * time.Hour

func newXrayClientCredential(protocol string) (string, error) {
	if protocol != xrayconfig.VLESS && protocol != xrayconfig.VMess {
		return randomToken(32)
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}

func xrayCredentialEnvelope(token string) (cipher.AEAD, error) {
	// The domain prefix separates the delivery key from the stored lookup hash.
	key := sha256.Sum256([]byte("MCUI-XRAY-CLIENT-DELIVERY-V1\n" + token))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func (s *Server) rotateXrayClientCredential(w http.ResponseWriter, r *http.Request) {
	ctx, ok := s.xrayClientAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		NodeID   string `json:"node_id"`
		Port     int    `json:"port"`
		Revision int64  `json:"revision"`
		MFACode  string `json:"mfa_code"`
	}
	username := r.PathValue("user")
	if readJSON(r, &in) != nil || !xrayconfig.ValidUsername(username) || !security.ValidNodeID(in.NodeID) ||
		in.Port < 1024 || in.Port > 65535 || in.Revision < 1 {
		http.Error(w, "invalid Xray credential request", http.StatusBadRequest)
		return
	}
	if !s.stepUp(ctx, in.MFACode) {
		http.Error(w, "MFA re-verification required", http.StatusPreconditionRequired)
		return
	}
	now, err := s.taskRuntime.currentTime()
	if err != nil {
		http.Error(w, "trusted task clock unavailable", http.StatusServiceUnavailable)
		return
	}
	var issued issuedClientShare
	err = s.store.Update(func(st *store.State) error {
		client, found := st.XrayClients[username]
		if !found || !s.panelXrayScope(st, lifecycleauth.Proposal{NodeID: in.NodeID, RequesterID: ctx.Admin.ID}) {
			return store.ErrNotFound
		}
		if client.Revision != in.Revision {
			return errClientRevision
		}
		index := slices.IndexFunc(client.Bindings, func(binding store.XrayClientBinding) bool {
			return binding.NodeID == in.NodeID && binding.Port == in.Port
		})
		if index < 0 {
			return store.ErrNotFound
		}
		if err := checkXrayDraftReservation(st, in.NodeID, now); err != nil {
			return err
		}
		node := st.Nodes[in.NodeID]
		inventory, _, err := panelInventory(node, now)
		if err != nil || inventory.Xray.PanelKey == "" || inventory.Xray.Version != xrayconfig.Version {
			return errXrayInventory
		}
		draft, err := xrayconfig.ParseConfiguration(node.XrayDraft)
		if err != nil || draft.Panel == nil || !hasClientBinding(draft.Inbounds, client.Bindings[index].XrayBinding) {
			return errClientCredential
		}
		position := inboundIndex(draft.Inbounds, in.Port)
		inbound := draft.Inbounds[position]
		credential, err := newXrayClientCredential(inbound.Protocol)
		if err != nil {
			return err
		}
		sealed, err := xrayconfig.SealPanelCredential(inventory.Xray.PanelKey, inbound, credential)
		if err != nil {
			return err
		}
		draft.Panel.Credentials[position] = sealed
		node.XrayDraft = draft.Encode()
		if len(node.XrayDraft) > xrayconfig.MaxConfigurationSize {
			return errXrayInventory
		}
		link, delivery, err := issueClientShare(username, now)
		if err != nil {
			return err
		}
		aead, err := xrayCredentialEnvelope(delivery.Token)
		if err != nil {
			return err
		}
		link.ExpiresAt = now.Add(xrayCredentialDeliveryLifetime).Unix()
		delivery.ExpiresAt = link.ExpiresAt
		digest := hash(sealed)
		client.Bindings[index].Delivery = store.CredentialDelivery{
			Link: link, CredentialHash: digest, Envelope: aead.Seal(nil, nil, []byte(credential), []byte(digest)),
		}
		client.Revision++
		st.XrayClients[username], st.Nodes[in.NodeID] = client, node
		s.auditXrayClient(st, ctx.Admin.ID, username, "credential.rotate", now)
		issued = delivery
		return nil
	})
	if err != nil {
		writeXrayClientResult(w, r, err, http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, issued)
}
