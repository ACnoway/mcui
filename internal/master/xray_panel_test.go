package master

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
	"github.com/ACnoway/mcui/internal/xraytraffic"
)

type testXrayReleaseCatalog struct {
	snapshot corecatalog.Snapshot
	assets   map[string]corecatalog.ReleaseArtifact
}

func (f *testXrayReleaseCatalog) List(context.Context) (corecatalog.Snapshot, error) {
	return f.snapshot, nil
}

func (f *testXrayReleaseCatalog) ListXrayReleases(context.Context) (corecatalog.Snapshot, error) {
	return f.snapshot, nil
}

func (f *testXrayReleaseCatalog) ResolveRelease(_ context.Context, core, version, arch, _ string) (corecatalog.ReleaseArtifact, error) {
	asset, ok := f.assets[version+"/"+arch]
	if !ok || core != "xray" {
		return corecatalog.ReleaseArtifact{}, errors.New("release fixture not found")
	}
	return asset, nil
}

func TestPanelXraySelectSignDeliverAndConfirm(t *testing.T) {
	testPanelXraySelectSignDeliverAndConfirm(t, nil)
}

func testTrojanTrust(t *testing.T) *xrayconfig.TrojanTrust {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
	if err != nil {
		t.Fatal(err)
	}
	text := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	sum, err := xrayconfig.TrojanCertificateDigest(text)
	if err != nil {
		t.Fatal(err)
	}
	return &xrayconfig.TrojanTrust{Certificate: text, SHA256: sum}
}

func testPanelXraySelectSignDeliverAndConfirm(t *testing.T, checkpoint func(*testing.T, taskTestClient)) {
	client := newTaskTestClient(t)
	const secondNodeID = "second-fixture-node"
	s := client.server
	s.EnableSingleAdmin()
	const secret = "JBSWY3DPEHPK3PXP"
	if err := client.store.Update(func(st *store.State) error {
		admin := st.Admins["operator-1"]
		admin.Role, admin.AllNodes, admin.TOTPSecret = "security_admin", true, secret
		st.Admins[admin.ID] = admin
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	generate := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return public, key
	}
	pub, key := generate()
	policyRaw, err := json.Marshal(map[string]any{
		"schema_version": 1, "signing_key_id": "xray-key",
		"signing_public_key": base64.StdEncoding.EncodeToString(pub),
		"panel":              map[string]any{"node_ids": []string{client.nodeID, secondNodeID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := lifecycleauth.ParsePolicy(policyRaw)
	if err != nil {
		t.Fatal(err)
	}
	trustedNow := func() (time.Time, error) { return time.Now().UTC(), nil }
	runtime := *s.taskRuntime
	runtime.XrayInstallPolicy, runtime.TrustedNow = policy, trustedNow
	if err := s.ConfigureTaskRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	if checkpoint != nil {
		checkpoint(t, client)
	}
	path := filepath.Join(t.TempDir(), "issuance.db")
	if err := lifecycleauth.InitLedger(path); err != nil {
		t.Fatal(err)
	}
	ledger, err := lifecycleauth.OpenLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	artifact := func(version, arch, fill string) corecatalog.ReleaseArtifact {
		t.Helper()
		digest := strings.Repeat(fill, 64)
		filename, err := corecatalog.ExpectedAssetName("xray", version, arch)
		if err != nil {
			t.Fatal(err)
		}
		return corecatalog.ReleaseArtifact{Core: "xray", Version: version, Architecture: arch, SHA256: digest,
			Filename: filename, Size: 1024, DownloadURL: "https://github.com/XTLS/Xray-core/releases/download/" + version + "/" + filename}
	}
	newer := artifact(xrayconfig.Version, "amd64", "b")
	older := artifact("v26.9.0", "amd64", "a")
	other := artifact("v26.11.0", "arm64", "c")
	assets := map[string]corecatalog.ReleaseArtifact{
		newer.Version + "/amd64": newer, older.Version + "/amd64": older, other.Version + "/arm64": other,
	}
	var releases []corecatalog.Release
	for _, asset := range []corecatalog.ReleaseArtifact{newer, older, other} {
		releases = append(releases, corecatalog.Release{Version: asset.Version, Assets: []corecatalog.Asset{{Name: asset.Filename, Size: asset.Size, DownloadURL: asset.DownloadURL}}})
	}
	s.coreCatalog = &testXrayReleaseCatalog{snapshot: corecatalog.Snapshot{Cores: []corecatalog.Core{{ID: "xray", Releases: releases}}}, assets: assets}
	token := strings.Repeat("k", 36)
	signer, err := lifecycleauth.NewPanelSignerHandler(policy, ledger, key, []byte(token), trustedNow)
	if err != nil {
		t.Fatal(err)
	}
	var dropResponse atomic.Bool
	dropResponse.Store(true)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/xray/issue" && dropResponse.Swap(false) {
			result := httptest.NewRecorder()
			signer.ServeHTTP(result, r)
			if result.Code != http.StatusOK {
				w.WriteHeader(result.Code)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		signer.ServeHTTP(w, r)
	}))
	defer service.Close()
	panelSigner, err := lifecycleauth.NewPanelSignerClient(service.URL, []byte(token))
	if err != nil || s.ConfigurePanelXray(panelSigner) != nil {
		t.Fatalf("configure panel signer: %v", err)
	}
	path = "/api/v1/admin/nodes/" + client.nodeID + "/xray"
	admin := func(method string, body any, csrf string) *httptest.ResponseRecorder {
		return requestAsAdmin(t, s.Handler(), method, "https://panel.example.test"+path, body, "test-session-token", csrf)
	}
	expect := func(r *httptest.ResponseRecorder, status int) {
		t.Helper()
		if r.Code != status {
			t.Fatalf("HTTP %d, want %d: %s", r.Code, status, r.Body)
		}
	}
	heartbeat := func(x *lifecycleauth.XrayInventory) {
		t.Helper()
		expect(client.request(http.MethodPost, "/api/v1/agent/heartbeat",
			map[string]any{"node_id": client.nodeID, "inventory": lifecycleauth.NodeInventory{Architecture: "amd64", Xray: x}},
			true), http.StatusOK)
	}
	options := func() (state string) {
		t.Helper()
		r := admin(http.MethodGet, nil, "")
		expect(r, http.StatusOK)
		var response struct {
			State    string                      `json:"state"`
			Versions []string                    `json:"versions"`
			Current  lifecycleauth.XrayInventory `json:"current"`
			Usage    struct {
				UserStatistics string `json:"user_statistics"`
				ExactQuota     string `json:"exact_quota"`
				Reason         string `json:"reason"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil ||
			!reflect.DeepEqual(response.Versions, []string{newer.Version, older.Version}) {
			t.Fatalf("invalid official version selection: %s, %v", r.Body, err)
		}
		reason := "capability_unverified"
		if response.Current.ConfigRevision != 0 {
			reason = "accounting_incomplete"
		}
		if (response.Usage.UserStatistics != "UNSUPPORTED" && (!response.Current.StatisticsActive || response.Usage.UserStatistics != "SAMPLED")) ||
			response.Usage.ExactQuota != "UNSUPPORTED" || response.Usage.Reason != reason {
			t.Fatalf("unsupported traffic or quota was not explicit: %+v", response.Usage)
		}
		return response.State
	}
	expect(admin(http.MethodGet, nil, ""), http.StatusConflict)
	heartbeat(&lifecycleauth.XrayInventory{})
	in := panelXrayRequest{TaskID: "install-fixture-1234567890", Operation: "core.install", Version: other.Version,
		State: options()}
	expect(admin(http.MethodPost, in, client.csrf), http.StatusConflict)
	in.Version = newer.Version
	expect(admin(http.MethodPost, in, "wrong-csrf"), http.StatusForbidden)
	expect(admin(http.MethodPost, in, client.csrf), http.StatusServiceUnavailable)
	expect(admin(http.MethodPost, in, client.csrf), http.StatusCreated)
	expect(admin(http.MethodPost, in, client.csrf), http.StatusOK)
	record, err := runtime.Store.GetRecord(in.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := policy.InstallKey().Verify(record.Raw)
	if err != nil || task.Sequence != 1 || task.Architecture != "amd64" || task.SignedManifest ||
		task.ManifestVersion != 0 || task.SHA256 != newer.SHA256 || task.Version != newer.Version {
		t.Fatalf("incorrect signed install: %+v %v", task, err)
	}
	if _, err := s.verifyStoredXrayTask(record.Raw, true); err != nil {
		t.Fatal(err)
	}
	completeNode := func(agent taskTestClient, id string, sequence int64, release corecatalog.ReleaseArtifact) {
		t.Helper()
		next := fmt.Sprintf("/api/v1/agent/tasks/next?next_sequence=%d&install=xray-official-v1&install_reconciliation=v1&xray_control=v1&xray_change=v1&xray_config=v1&xray_plan=v1&xray_http=v1&xray_protocols=v1&xray_trojan_tls=v1&xray_reality=v1&xray_public=v1&xray_routing=v1", sequence)
		expect(agent.request(http.MethodGet, next, nil, true), http.StatusOK)
		result, err := json.Marshal(lifecycleauth.InstallResult{Outcome: "SUCCEEDED", Version: release.Version, SHA256: release.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		expect(agent.request(http.MethodPost, "/api/v1/agent/tasks/ack", taskAckRequest{TaskID: id, Sequence: sequence, StatusVersion: 1,
			Status: "SUCCEEDED", Result: result}, true), http.StatusNoContent)
	}
	complete := func(id string, sequence int64, release corecatalog.ReleaseArtifact) {
		t.Helper()
		completeNode(client, id, sequence, release)
	}
	complete(in.TaskID, 1, newer)
	heartbeat(&lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256, Running: true})
	change := panelXrayRequest{TaskID: "downgrade-fixture-1234567890", Operation: "core.downgrade", Version: older.Version,
		State: options()}
	expect(admin(http.MethodPost, change, client.csrf), http.StatusBadRequest)
	change.Confirm = change.Operation
	expect(admin(http.MethodPost, change, client.csrf), http.StatusPreconditionRequired)
	totpKey, _ := base32Decode(secret)
	change.MFACode = fmtCode(totpAt(totpKey, time.Now().Unix()/30))
	expect(admin(http.MethodPost, change, client.csrf), http.StatusCreated)
	changed, err := runtime.Store.GetRecord(change.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err = policy.InstallKey().Verify(changed.Raw)
	if err != nil || task.Sequence != 2 || task.SHA256 != older.SHA256 || task.CurrentSHA256 != newer.SHA256 ||
		task.CurrentVersion != newer.Version || task.Operation != change.Operation {
		t.Fatalf("incorrect signed downgrade: %+v %v", task, err)
	}
	complete(change.TaskID, 2, older)
	heartbeat(&lifecycleauth.XrayInventory{Version: older.Version, SHA256: older.SHA256})
	upgrade := panelXrayRequest{TaskID: "upgrade-fixture-1234567890", Operation: "core.upgrade", Version: newer.Version,
		State: options()}
	expect(admin(http.MethodPost, upgrade, client.csrf), http.StatusCreated)
	complete(upgrade.TaskID, 3, newer)
	config := xrayconfig.Reference{Port: 1080, SHA256: strings.Repeat("d", 64), Size: 350}
	node := lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256, Running: true, Candidate: config}
	heartbeat(&node)
	apply := panelXrayRequest{TaskID: "config-fixture-1234567890", Operation: xrayconfig.Operation, Version: newer.Version,
		State: options(), Confirm: xrayconfig.Operation}
	expect(admin(http.MethodPost, apply, client.csrf), http.StatusPreconditionRequired)
	apply.MFACode = fmtCode(totpAt(totpKey, time.Now().Unix()/30))
	node.Candidate.Port++
	heartbeat(&node)
	expect(admin(http.MethodPost, apply, client.csrf), http.StatusConflict)
	node.Candidate = config
	heartbeat(&node)
	expect(admin(http.MethodPost, apply, client.csrf), http.StatusCreated)
	signed, err := runtime.Store.GetRecord(apply.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err = policy.InstallKey().Verify(signed.Raw)
	if err != nil || task.Sequence != 4 || task.Operation != xrayconfig.Operation || task.Config != config || task.SHA256 != newer.SHA256 {
		t.Fatalf("incorrect signed configuration: %+v %v", task, err)
	}
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=4&install=xray-official-v1", nil, true), http.StatusNoContent)
	complete(apply.TaskID, 4, newer)

	node.PlanSupported, node.Candidate = true, xrayconfig.Reference{}
	trust := testTrojanTrust(t)
	realityKey, err := xrayconfig.RealityPublicKey(strings.Repeat("Q", 43))
	if err != nil {
		t.Fatal(err)
	}
	publicEndpoint := xrayconfig.PublicEndpoint{Address: "93.184.216.35", Port: 443}
	node.Catalog = &xrayconfig.Catalog{
		Ports: []int{1080, 1081, 1082, 1083}, Users: []string{"alice", "bob"}, HTTPPorts: []int{1080},
		PortProtocols: map[int]string{1082: xrayconfig.VLESSReality, 1083: xrayconfig.Trojan},
		ProtocolUsers: map[string][]string{xrayconfig.VLESSReality: {"carol"}, xrayconfig.Trojan: {"dave"}}, TrojanTrust: trust,
		RealityPublicKey: realityKey,
		PublicEndpoints:  map[int]xrayconfig.PublicEndpoint{1083: publicEndpoint},
	}
	node.Config, node.ConfigRevision = config, 4
	heartbeat(&node)
	draftPath := "https://panel.example.test" + path + "/draft"
	plan := xrayconfig.Plan{
		{Port: 1080, Protocol: xrayconfig.HTTP, Users: []string{"bob"}}, {Port: 1081, Users: []string{"alice", "bob"}},
		{Port: 1082, Protocol: xrayconfig.VLESSReality, RealityPublicKey: realityKey, Users: []string{"carol"}},
		{Port: 1083, Protocol: xrayconfig.Trojan, TLSCertSHA256: trust.SHA256, PublicEndpoint: publicEndpoint, Users: []string{"dave"}},
	}
	body := map[string]any{"state": options(), "plan": plan}
	save := func(url, csrf string) *httptest.ResponseRecorder {
		return requestAsAdmin(t, s.Handler(), http.MethodPut, url, body, "test-session-token", csrf)
	}
	expect(save(draftPath, ""), http.StatusForbidden)
	expect(save(strings.Replace(draftPath, client.nodeID, "outside-scope", 1), client.csrf), http.StatusNotFound)
	expect(save(draftPath, client.csrf), http.StatusOK)
	previous := body["state"]
	body["plan"] = xrayconfig.Plan{}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["state"] = options()
	body["plan"] = xrayconfig.Plan{{Port: 1081, Users: []string{"outside"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["plan"] = xrayconfig.Plan{{Port: 1080, Users: []string{"bob"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["plan"] = xrayconfig.Plan{{Port: 1082, Protocol: xrayconfig.VLESSReality, RealityPublicKey: realityKey, Users: []string{"alice"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["plan"] = xrayconfig.Plan{{Port: 1082, Protocol: xrayconfig.VLESSReality, RealityPublicKey: strings.Repeat("M", 43), Users: []string{"carol"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["plan"] = xrayconfig.Plan{{Port: 1083, Protocol: xrayconfig.Trojan, TLSCertSHA256: strings.Repeat("f", 64), PublicEndpoint: publicEndpoint, Users: []string{"dave"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["plan"] = xrayconfig.Plan{{Port: 1083, Protocol: xrayconfig.Trojan, TLSCertSHA256: trust.SHA256, Users: []string{"dave"}}}
	expect(save(draftPath, client.csrf), http.StatusConflict)
	body["state"], body["plan"] = previous, plan
	expect(save(draftPath, client.csrf), http.StatusOK) // Lost-response retry.
	managed := apply
	managed.TaskID = "managed-fixture-1234567890"
	managed.State, managed.MFACode = options(), fmtCode(totpAt(totpKey, time.Now().Unix()/30))
	expect(admin(http.MethodPost, managed, client.csrf), http.StatusConflict)
	node.Candidate = xrayconfig.Reference{Port: 1080, SHA256: strings.Repeat("e", 64), Size: 420}
	node.Preview = xrayconfig.PlanDigest(plan.Encode())
	heartbeat(&node)
	managed.State = options()
	expect(admin(http.MethodPost, managed, client.csrf), http.StatusCreated)
	signed, err = runtime.Store.GetRecord(managed.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	task, err = policy.InstallKey().Verify(signed.Raw)
	if err != nil || task.Sequence != 5 || task.Config != node.Candidate || task.Plan != plan.Encode() {
		t.Fatalf("signed task did not bind plan and configuration: %+v %v", task, err)
	}
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1", nil, true), http.StatusNoContent)
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1&xray_plan=v1", nil, true), http.StatusNoContent)
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_http=v1", nil, true), http.StatusNoContent)
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_http=v1&xray_protocols=v1", nil, true), http.StatusNoContent)
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_http=v1&xray_protocols=v1&xray_trojan_tls=v1", nil, true), http.StatusNoContent)
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_http=v1&xray_protocols=v1&xray_trojan_tls=v1&xray_reality=v1", nil, true), http.StatusNoContent)
	complete(managed.TaskID, 5, newer)

	subscriptionPath := "https://panel.example.test" + path + "/subscriptions"
	subscriptionAdmin := func(method, url, csrf string, request any) *httptest.ResponseRecorder {
		return requestAsAdmin(t, s.Handler(), method, url, request, "test-session-token", csrf)
	}
	nextIP := 1
	fetch := func(url, token, remote string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, url, nil)
		if remote == "" {
			remote = fmt.Sprintf("192.0.2.%d:1234", nextIP)
			nextIP++
		}
		request.RemoteAddr = remote
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, request)
		return response
	}
	const publicURL = "https://panel.example.test/api/v1/subscription"
	newToken := func(user string) string {
		t.Helper()
		request := map[string]string{"action": "issue", "username": user, "mfa_code": fmtCode(totpAt(totpKey, time.Now().Unix()/30))}
		r := subscriptionAdmin(http.MethodPost, subscriptionPath, client.csrf, request)
		expect(r, http.StatusOK)
		var reply struct {
			Token     string `json:"token"`
			ExpiresAt int64  `json:"expires_at"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &reply); err != nil || !strings.HasPrefix(reply.Token, client.nodeID+".") ||
			reply.ExpiresAt < time.Now().Add(29*24*time.Hour).Unix() {
			t.Fatalf("invalid issue response: %v", err)
		}
		return reply.Token
	}
	var currentToken string
	// Subscription tests reuse the same signed and acknowledged lifecycle.
	{
		request := map[string]string{"action": "issue", "username": "alice"}
		expect(subscriptionAdmin(http.MethodPost, subscriptionPath, client.csrf, request), http.StatusConflict)
		node.Applied, node.Config, node.ConfigRevision = &plan, node.Candidate, 5
		heartbeat(&node)
		expect(subscriptionAdmin(http.MethodPost, subscriptionPath, "", request), http.StatusForbidden)
		expect(subscriptionAdmin(http.MethodPost, strings.Replace(subscriptionPath, client.nodeID, "outside-scope", 1), client.csrf, request), http.StatusNotFound)
		if err := s.runWithTaskState(t.Context(), func() error {
			return client.store.Update(func(st *store.State) error {
				for id, session := range st.Sessions {
					session.MFAAt = 0
					st.Sessions[id] = session
				}
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		expect(subscriptionAdmin(http.MethodPost, subscriptionPath, client.csrf, request), http.StatusPreconditionRequired)
		alice := newToken("alice")
		expect(subscriptionAdmin(http.MethodPost, subscriptionPath, client.csrf,
			map[string]string{"action": "issue", "username": "outside"}), http.StatusConflict)
		bob := newToken("bob")
		expect(fetch(publicURL, alice, ""), http.StatusOK)
		multi := fetch(publicURL, bob, "")
		expect(multi, http.StatusOK)
		if !strings.Contains(multi.Body.String(), `"ports":[1080,1081]`) || !strings.Contains(multi.Body.String(), `"http_ports":[1080]`) ||
			!strings.Contains(multi.Body.String(), `"schema_version":2`) || strings.Contains(multi.Body.String(), "alice") {
			t.Fatalf("wrong ports or another user's data: %s", multi.Body)
		}
		single := fetch(publicURL, alice, "")
		expect(single, http.StatusOK)
		if !strings.Contains(single.Body.String(), `"ports":[1081]`) || !strings.Contains(single.Body.String(), `"schema_version":1`) ||
			strings.Contains(single.Body.String(), `"http_ports"`) || strings.Contains(single.Body.String(), "bob") ||
			strings.Contains(single.Body.String(), alice) || single.Header().Get("Cache-Control") != "no-store" ||
			single.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("subscription response violated port scope or privacy headers")
		}
		reality := fetch(publicURL, newToken("carol"), "")
		expect(reality, http.StatusOK)
		if !strings.Contains(reality.Body.String(), `"schema_version":3`) || !strings.Contains(reality.Body.String(), `"port_protocols":{"1082":"vless-reality"}`) ||
			!strings.Contains(reality.Body.String(), `"ports":[1082]`) || !strings.Contains(reality.Body.String(), `"reality_public_key":"`+realityKey+`"`) ||
			strings.Contains(reality.Body.String(), `"http_ports"`) || strings.Contains(reality.Body.String(), `"trojan_trust"`) ||
			strings.Contains(reality.Body.String(), `"public_endpoints"`) {
			t.Fatal("REALITY subscription did not bind the authorized port and public key")
		}
		dave := newToken("dave")
		response := fetch(publicURL, dave, "")
		expect(response, http.StatusOK)
		var trojan struct {
			Trust     xrayconfig.TrojanTrust            `json:"trojan_trust"`
			Version   int                               `json:"schema_version"`
			Published map[int]xrayconfig.PublicEndpoint `json:"public_endpoints"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &trojan); err != nil || trojan.Trust != *trust ||
			trojan.Version != 4 || len(trojan.Published) != 1 || trojan.Published[1083] != publicEndpoint ||
			!strings.Contains(response.Body.String(), `"port_protocols":{"1083":"trojan"}`) || strings.Contains(response.Body.String(), `"reality_public_key"`) {
			t.Fatalf("Trojan subscription did not carry the approved TLS identity: %v", err)
		}
		otherTrust := testTrojanTrust(t)
		otherPlan := append(xrayconfig.Plan(nil), plan...)
		otherPlan[3].TLSCertSHA256 = otherTrust.SHA256
		node.Catalog.TrojanTrust, node.Applied = otherTrust, &otherPlan
		heartbeat(&node)
		expect(fetch(publicURL, dave, ""), http.StatusNotFound)
		node.Catalog.TrojanTrust, node.Applied = trust, &plan
		heartbeat(&node)
		expect(fetch(strings.Replace(publicURL, "https:", "http:", 1), alice, ""), http.StatusNotFound)
		expect(fetch(publicURL+"?token="+alice, "", ""), http.StatusNotFound)
		expect(fetch(publicURL, strings.Replace(alice, client.nodeID, "outside-scope", 1), ""), http.StatusNotFound)
		list := subscriptionAdmin(http.MethodGet, subscriptionPath, "", nil)
		expect(list, http.StatusOK)
		if strings.Contains(list.Body.String(), alice) || strings.Contains(list.Body.String(), hash(alice)) {
			t.Fatal("list exposed a token or digest")
		}
		if err := client.store.View(func(st store.State) error {
			raw, err := json.Marshal(st)
			if err != nil || strings.Contains(string(raw), alice) ||
				st.Nodes[client.nodeID].XraySubscriptions["alice"].TokenHash != hash(alice) {
				t.Fatal("token persistence did not contain only the digest")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		rotated := newToken("alice")
		expect(fetch(publicURL, alice, ""), http.StatusNotFound)
		expect(fetch(publicURL, rotated, ""), http.StatusOK)
		expect(subscriptionAdmin(http.MethodPost, subscriptionPath, client.csrf,
			map[string]string{"action": "revoke", "username": "alice"}), http.StatusOK)
		expect(fetch(publicURL, rotated, ""), http.StatusNotFound)
		alice = newToken("alice")

		if err := s.runWithTaskState(t.Context(), func() error {
			return client.store.Update(func(st *store.State) error {
				n := st.Nodes[client.nodeID]
				entry := n.XraySubscriptions["bob"]
				entry.ExpiresAt = time.Now().Unix() - 1
				n.XraySubscriptions["bob"] = entry
				st.Nodes[n.ID] = n
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		expect(fetch(publicURL, bob, ""), http.StatusNotFound)
		bob = newToken("bob")
		forged := xrayconfig.Plan{{Port: 1080, Protocol: xrayconfig.HTTP, Users: []string{"alice", "bob"}}}
		node.Applied = &forged
		heartbeat(&node)
		expect(fetch(publicURL, alice, ""), http.StatusNotFound)
		node.Applied = &plan
		heartbeat(&node)

		reduced := xrayconfig.Plan{{Port: 1080, Protocol: xrayconfig.HTTP, Users: []string{"bob"}}}
		target := xrayconfig.Destination{Address: "93.184.216.34", Port: 443}
		network := &xrayconfig.Network{
			Outbounds: []xrayconfig.Outbound{{Tag: "web", Destination: target}},
			Routes:    []xrayconfig.Route{{InboundPort: 1080, OutboundTag: "web"}},
		}
		body["network"] = network
		body["state"], body["plan"] = options(), reduced
		expect(save(draftPath, client.csrf), http.StatusConflict)
		node.Catalog.RoutingDestinations = []xrayconfig.Destination{target}
		heartbeat(&node)
		body["state"] = options()
		expect(save(draftPath, client.csrf), http.StatusOK)
		expect(fetch(publicURL, bob, ""), http.StatusOK) // A draft does not change active grants.
		node.Candidate = xrayconfig.Reference{Port: 1080, SHA256: strings.Repeat("f", 64), Size: 360}
		approvedDraft := xrayconfig.Configuration{Inbounds: reduced, Network: network}
		node.Preview = xrayconfig.PlanDigest(approvedDraft.Encode())
		heartbeat(&node)
		removeAlice := managed
		removeAlice.TaskID = "reduced-config-fixture-0123456789"
		removeAlice.State, removeAlice.MFACode = options(), fmtCode(totpAt(totpKey, time.Now().Unix()/30))
		expect(admin(http.MethodPost, removeAlice, client.csrf), http.StatusCreated)
		expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=6&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_http=v1&xray_protocols=v1&xray_trojan_tls=v1&xray_reality=v1&xray_public=v1", nil, true), http.StatusNoContent)
		expect(fetch(publicURL, alice, ""), http.StatusNotFound)
		complete(removeAlice.TaskID, 6, newer)
		expect(fetch(publicURL, bob, ""), http.StatusNotFound) // ACK arrived before the new heartbeat.
		node.Applied, node.Config, node.ConfigRevision = &reduced, node.Candidate, 6
		node.AppliedNetwork = network
		heartbeat(&node)
		expect(fetch(publicURL, alice, ""), http.StatusNotFound)
		expect(fetch(publicURL, bob, ""), http.StatusNotFound)
		currentToken = newToken("bob")
		fresh := fetch(publicURL, currentToken, "")
		expect(fresh, http.StatusOK)
		if !strings.Contains(fresh.Body.String(), `"ports":[1080]`) {
			t.Fatalf("fresh subscription retained obsolete ports: %s", fresh.Body)
		}
		invalid := client.nodeID + "." + strings.Repeat("A", 43)
		for range 10 {
			expect(fetch(publicURL, invalid, "192.0.2.200:1234"), http.StatusNotFound)
		}
		expect(fetch(publicURL, invalid, "192.0.2.200:1234"), http.StatusTooManyRequests)
	}
	t.Run("client bindings and links across nodes", func(t *testing.T) {
		expect := func(r *httptest.ResponseRecorder, status int) {
			t.Helper()
			if r.Code != status {
				t.Fatalf("HTTP %d, want %d: %s", r.Code, status, r.Body)
			}
		}
		second := client
		second.nodeID = secondNodeID
		second.token, err = randomToken(32)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.runWithTaskState(t.Context(), func() error {
			return client.store.Update(func(st *store.State) error {
				st.Nodes[secondNodeID] = store.Node{ID: secondNodeID, Name: "second node", Enrolled: true, TokenHash: hash(second.token)}
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		secondInventory := lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256, Running: true, PlanSupported: true,
			Catalog: &xrayconfig.Catalog{Ports: []int{1080}, Users: []string{"native"}}}
		secondHeartbeat := func() {
			t.Helper()
			expect(second.request(http.MethodPost, "/api/v1/agent/heartbeat",
				map[string]any{"node_id": secondNodeID, "inventory": lifecycleauth.NodeInventory{Architecture: "amd64", Xray: &secondInventory}}, true), http.StatusOK)
		}
		secondHeartbeat()
		const clientsURL = "https://panel.example.test/api/v1/admin/xray/clients"
		central := func(method, suffix string, body any) *httptest.ResponseRecorder {
			return subscriptionAdmin(method, clientsURL+suffix, client.csrf, body)
		}
		create := map[string]string{"username": "customer"}
		expect(subscriptionAdmin(http.MethodPost, clientsURL, "", create), http.StatusForbidden)
		expect(central(http.MethodPost, "", create), http.StatusCreated)
		expect(central(http.MethodPost, "", create), http.StatusConflict)
		first := store.XrayBinding{NodeID: client.nodeID, Port: 1080, Credential: "bob"}
		other := store.XrayBinding{NodeID: secondNodeID, Port: 1080, Credential: "native"}
		bind := func(revision int, bindings ...store.XrayBinding) *httptest.ResponseRecorder {
			return central(http.MethodPut, "/customer/bindings", map[string]any{"revision": revision, "bindings": bindings})
		}
		unapproved := other
		unapproved.Credential = "not-registered"
		expect(bind(1, first, unapproved), http.StatusConflict)
		expect(bind(1, first, other), http.StatusOK)
		expect(bind(1, first, other), http.StatusOK) // A retried save keeps the prior revision and shares.
		expect(bind(1, other), http.StatusConflict)
		expect(central(http.MethodPost, "", map[string]string{"username": "another"}), http.StatusCreated)
		expect(central(http.MethodPut, "/another/bindings", map[string]any{"revision": 1, "bindings": []store.XrayBinding{other}}), http.StatusConflict)
		expect(subscriptionAdmin(http.MethodPut, "https://panel.example.test"+path+"/draft", client.csrf,
			map[string]any{"state": options(), "plan": xrayconfig.Plan{}}), http.StatusConflict)
		issue := func(body map[string]any) clientShareResult {
			t.Helper()
			r := central(http.MethodPost, "/customer/share", body)
			expect(r, http.StatusOK)
			var issued clientShareResult
			if err := json.Unmarshal(r.Body.Bytes(), &issued); err != nil {
				t.Fatal(err)
			}
			return issued
		}
		issued := issue(map[string]any{"action": "issue"})
		if issued.Subscription == nil || len(issued.Inbounds) != 1 || issued.Inbounds[0].XrayBinding != first {
			t.Fatal("pending binding received a share")
		}
		const aggregateURL = "https://panel.example.test/api/v1/client-subscription"
		getEntries := func(token string) []clientSubscriptionEntry {
			t.Helper()
			r := fetch(aggregateURL, token, "")
			expect(r, http.StatusOK)
			var payload struct {
				Username string                    `json:"username"`
				Entries  []clientSubscriptionEntry `json:"entries"`
			}
			if err := json.Unmarshal(r.Body.Bytes(), &payload); err != nil || payload.Username != "customer" {
				t.Fatalf("invalid client subscription: %v", err)
			}
			return payload.Entries
		}
		aggregate := issued.Subscription.Token
		firstLink := issued.Inbounds[0].Token
		if entries := getEntries(aggregate); len(entries) != 1 || entries[0].NodeID != client.nodeID || entries[0].Config["username"] != "bob" {
			t.Fatal("aggregate did not filter pending bindings or retain the local credential name")
		}
		secondPlan := xrayconfig.Plan{{Port: 1080, Users: []string{"native"}}}
		secondInventory.Candidate = xrayconfig.Reference{Port: 1080, SHA256: strings.Repeat("a", 64), Size: 500}
		secondInventory.Preview = xrayconfig.PlanDigest(secondPlan.Encode())
		secondHeartbeat()
		secondURL := strings.Replace("https://panel.example.test"+path, client.nodeID, secondNodeID, 1)
		secondOptions := subscriptionAdmin(http.MethodGet, secondURL, "", nil)
		expect(secondOptions, http.StatusOK)
		var secondState struct{ State string }
		if err := json.Unmarshal(secondOptions.Body.Bytes(), &secondState); err != nil {
			t.Fatal(err)
		}
		newTask := apply
		newTask.TaskID, newTask.State = "second-node-config-0123456789", secondState.State
		newTask.MFACode = fmtCode(totpAt(totpKey, time.Now().Unix()/30))
		expect(subscriptionAdmin(http.MethodPost, secondURL, client.csrf, newTask), http.StatusCreated)
		completeNode(second, newTask.TaskID, 1, newer)
		secondInventory.Applied, secondInventory.Config, secondInventory.ConfigRevision = &secondPlan, secondInventory.Candidate, 1
		secondHeartbeat()
		if entries := getEntries(aggregate); len(entries) != 2 || entries[0].NodeID == entries[1].NodeID {
			t.Fatal("existing aggregate did not pick up the second node with the same port")
		}
		if entries := getEntries(firstLink); len(entries) != 1 || entries[0].NodeID != client.nodeID {
			t.Fatal("single-inbound link escaped its node")
		}
		secondLink := issue(map[string]any{"action": "issue", "node_id": secondNodeID, "port": 1080})
		if secondLink.Subscription != nil || len(secondLink.Inbounds) != 1 || secondLink.Inbounds[0].XrayBinding != other {
			t.Fatal("issuing one inbound affected the aggregate token")
		}
		expect(bind(2, other), http.StatusOK)
		expect(fetch(aggregateURL, firstLink, ""), http.StatusNotFound)
		if entries := getEntries(aggregate); len(entries) != 1 || entries[0].NodeID != secondNodeID {
			t.Fatal("removed binding remained in the aggregate before node apply")
		}
		listed := central(http.MethodGet, "", nil)
		expect(listed, http.StatusOK)
		if strings.Contains(listed.Body.String(), aggregate) || !strings.Contains(listed.Body.String(), `"applied":true`) {
			t.Fatal("admin list did not report applied status safely")
		}
		expect(central(http.MethodPost, "/customer/share", map[string]any{"action": "revoke"}), http.StatusOK)
		expect(fetch(aggregateURL, aggregate, ""), http.StatusNotFound)
		expect(fetch(aggregateURL, secondLink.Inbounds[0].Token, ""), http.StatusNotFound)
	})

	for i, operation := range []string{"core.start", "core.stop", "core.uninstall"} {
		heartbeat(&node)
		id := fmt.Sprintf("control-fixture-%010d", i)
		control := panelXrayRequest{TaskID: id, Operation: operation, State: options()}
		if control.dangerous() {
			control.Confirm, control.MFACode = operation, fmtCode(totpAt(totpKey, time.Now().Unix()/30))
		}
		expect(admin(http.MethodPost, control, client.csrf), http.StatusCreated)
		complete(id, int64(i)+7, newer)
		if operation == "core.stop" {
			expect(fetch(publicURL, currentToken, ""), http.StatusNotFound)
			node.Running = false
		}
	}
	t.Run("panel Trojan binds the public socket and encrypted identity", func(t *testing.T) {
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.runWithTaskState(t.Context(), func() error {
			return s.store.Update(func(st *store.State) error {
				registered := st.Nodes[client.nodeID]
				registered.XrayDraft = "[]"
				st.Nodes[client.nodeID] = registered
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		direct := lifecycleauth.XrayInventory{
			PlanSupported: true,
			PanelKey:      base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), PanelTrojan: true,
			PanelAddresses: []string{"93.184.216.36"},
		}
		heartbeat(&direct)
		installDirect := panelXrayRequest{TaskID: "panel-inbound-reinstall-12345", Operation: "core.install",
			Version: newer.Version, State: options(), MFACode: fmtCode(totpAt(totpKey, time.Now().Unix()/30))}
		expect(admin(http.MethodPost, installDirect, client.csrf), http.StatusCreated)
		installed, err := runtime.Store.GetRecord(installDirect.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		installTask, err := policy.InstallKey().Verify(installed.Raw)
		if err != nil {
			t.Fatal(err)
		}
		complete(installDirect.TaskID, installTask.Sequence, newer)
		direct.Version, direct.SHA256, direct.Running = newer.Version, newer.SHA256, true
		heartbeat(&direct)
		credential := strings.Repeat("A", 43)
		change := panelInboundChange{
			State: options(), Protocol: xrayconfig.Trojan, Username: "alice", Credential: credential,
			Destination: xrayconfig.Destination{Address: "93.184.216.34", Port: 443},
			Public:      xrayconfig.PublicEndpoint{Address: "93.184.216.35", Port: 443},
		}
		write := func(csrf string) *httptest.ResponseRecorder {
			return requestAsAdmin(t, s.Handler(), http.MethodPut, "https://panel.example.test"+path+"/inbounds/1080", change,
				"test-session-token", csrf)
		}
		expect(write("incorrect-csrf"), http.StatusForbidden)
		expect(write(client.csrf), http.StatusBadRequest)
		change.Public.Address = direct.PanelAddresses[0]
		expect(write(client.csrf), http.StatusOK)
		expect(write(client.csrf), http.StatusConflict)
		change.State = options()
		change.Username, change.Credential = "", ""
		change.Clients = []panelInboundClient{
			{Username: "bob", Credential: strings.Repeat("E", 43)},
			{Username: "alice"},
		}
		expect(write(client.csrf), http.StatusConflict)
		direct.PanelMultiClient = true
		heartbeat(&direct)
		change.State = options()
		expect(write(client.csrf), http.StatusOK)
		registered, err := s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil || registered.XrayPanelKey != direct.PanelKey || strings.Contains(registered.XrayDraft, credential) {
			t.Fatalf("credential persisted or node key not pinned: %v", err)
		}
		config, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || config.Panel == nil || config.Panel.TLS == nil || !config.Panel.TLS.Trust.Valid() || config.Inbounds[0].PublicEndpoint != change.Public {
			t.Fatalf("public endpoint or TLS identity missing from draft: %v", err)
		}
		saveNetwork := func(plan xrayconfig.Plan, network *xrayconfig.Network) *httptest.ResponseRecorder {
			return subscriptionAdmin(http.MethodPut, "https://panel.example.test"+path+"/draft", client.csrf,
				map[string]any{"state": options(), "plan": plan, "network": network})
		}
		network := &xrayconfig.Network{
			Outbounds: []xrayconfig.Outbound{
				{Tag: "primary", Destination: change.Destination},
				{Tag: "spare", Destination: xrayconfig.Destination{Address: "93.184.216.37", Port: 443}},
			},
			Routes: []xrayconfig.Route{{InboundPort: 1080, OutboundTag: "primary"}},
		}
		expect(saveNetwork(xrayconfig.Plan{}, &xrayconfig.Network{Outbounds: network.Outbounds, Routes: []xrayconfig.Route{}}), http.StatusConflict)
		duplicateRoute := *network
		duplicateRoute.Routes = append(append([]xrayconfig.Route{}, network.Routes...), network.Routes[0])
		expect(saveNetwork(config.Inbounds, &duplicateRoute), http.StatusBadRequest)
		network.Routes = append(network.Routes, xrayconfig.Route{InboundPort: 1080, OutboundTag: "spare"})
		expect(saveNetwork(config.Inbounds, network), http.StatusConflict)
		direct.PanelMultiRoute = true
		heartbeat(&direct)
		expect(saveNetwork(config.Inbounds, network), http.StatusOK)
		copyChange := panelInboundChange{
			State: options(), Protocol: xrayconfig.Trojan, CopyRoutesFrom: 1080,
			Clients: []panelInboundClient{{Username: "alice", Credential: strings.Repeat("I", 43)},
				{Username: "bob", Credential: strings.Repeat("M", 43)}},
		}
		copyInbound := func(change panelInboundChange) *httptest.ResponseRecorder {
			return subscriptionAdmin(http.MethodPut, "https://panel.example.test"+path+"/inbounds/1081", client.csrf, change)
		}
		expect(copyInbound(copyChange), http.StatusOK)
		copiedNode, err := s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		copied, err := xrayconfig.ParseConfiguration(copiedNode.XrayDraft)
		if err != nil || len(copied.Inbounds) != 2 || len(copied.Network.Routes) != 4 ||
			copied.Network.Routes[2] != (xrayconfig.Route{InboundPort: 1081, OutboundTag: "primary"}) ||
			copied.Network.Routes[3] != (xrayconfig.Route{InboundPort: 1081, OutboundTag: "spare"}) ||
			copied.Panel.Credentials[0] == copied.Panel.Credentials[2] {
			t.Fatalf("copied inbound did not preserve routes and independent credentials: %v", err)
		}
		if _, _, err := copied.RenderPanel(private); err != nil {
			t.Fatalf("copied credentials did not decrypt on the new port: %v", err)
		}
		copyChange.State = options()
		expect(copyInbound(copyChange), http.StatusConflict)
		expect(copyInbound(panelInboundChange{State: options(), Remove: true}), http.StatusOK)
		change.State, change.Destination = options(), xrayconfig.Destination{}
		change.Clients[0].Credential = ""
		expect(write(client.csrf), http.StatusOK)
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		routed, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || !reflect.DeepEqual(routed.Panel, config.Panel) || !reflect.DeepEqual(routed.Network, network) {
			t.Fatalf("network save changed credentials or omitted an explicit outbound: %v", err)
		}
		config = routed
		statsChange := func() *httptest.ResponseRecorder {
			return subscriptionAdmin(http.MethodPut, "https://panel.example.test"+path+"/draft", client.csrf,
				map[string]any{"state": options(), "plan": config.Inbounds, "network": network, "statistics": true})
		}
		expect(statsChange(), http.StatusConflict)
		direct.PanelStatistics = true
		heartbeat(&direct)
		expect(statsChange(), http.StatusOK)
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		config, err = xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || !config.Panel.Statistics {
			t.Fatalf("draft did not enable statistics: %v", err)
		}
		const clientsURL = "https://panel.example.test/api/v1/admin/xray/clients"
		const aggregateURL = "https://panel.example.test/api/v1/client-subscription"
		central := func(method, suffix string, body any) *httptest.ResponseRecorder {
			return subscriptionAdmin(method, clientsURL+suffix, client.csrf, body)
		}
		legacy := store.XrayBinding{NodeID: secondNodeID, Port: 1080, Credential: "native"}
		published := store.XrayBinding{NodeID: client.nodeID, Port: 1080, Credential: "alice"}
		listed := central(http.MethodGet, "", nil)
		expect(listed, http.StatusOK)
		if !strings.Contains(listed.Body.String(), `"panel_inbounds":true`) || strings.Contains(listed.Body.String(), credential) ||
			strings.Contains(listed.Body.String(), config.Panel.Credentials[0]) {
			t.Fatal("client options must expose the panel account name without its credential")
		}
		bind := func(revision int, bindings ...store.XrayBinding) *httptest.ResponseRecorder {
			return central(http.MethodPut, "/customer/bindings", map[string]any{"revision": revision, "bindings": bindings})
		}
		unknown := published
		unknown.Credential = "not-registered"
		expect(bind(3, legacy, unknown), http.StatusConflict)
		expect(bind(3, legacy, published), http.StatusOK)
		expect(subscriptionAdmin(http.MethodPut, "https://panel.example.test"+path+"/inbounds/1080", client.csrf,
			panelInboundChange{State: options(), Remove: true}), http.StatusConflict)
		expect(central(http.MethodPost, "/customer/share", map[string]any{"action": "issue", "node_id": client.nodeID, "port": 1080}), http.StatusConflict)
		share := func() clientShareResult {
			t.Helper()
			r := central(http.MethodPost, "/customer/share", map[string]any{"action": "issue"})
			expect(r, http.StatusOK)
			var result clientShareResult
			if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil || result.Subscription == nil {
				t.Fatalf("invalid client share: %v", err)
			}
			return result
		}
		pendingShare := share()
		if len(pendingShare.Inbounds) != 1 || pendingShare.Inbounds[0].XrayBinding != legacy {
			t.Fatal("unapplied panel inbound received a share")
		}
		applyDirect := panelXrayRequest{TaskID: "panel-inbound-fixture-12345", Operation: xrayconfig.Operation, Confirm: xrayconfig.Operation,
			Version: newer.Version, State: options(), MFACode: fmtCode(totpAt(totpKey, time.Now().Unix()/30))}
		expect(admin(http.MethodPost, applyDirect, client.csrf), http.StatusConflict)
		_, direct.Candidate, err = config.RenderPanel(private)
		if err != nil {
			t.Fatal(err)
		}
		direct.Preview = xrayconfig.PlanDigest(registered.XrayDraft)
		heartbeat(&direct)
		applyDirect.State = options()
		expect(admin(http.MethodPost, applyDirect, client.csrf), http.StatusCreated)
		stored, err := runtime.Store.GetRecord(applyDirect.TaskID)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := policy.InstallKey().Verify(stored.Raw)
		if err != nil || issued.Plan != registered.XrayDraft || issued.Config != direct.Candidate {
			t.Fatalf("signed task does not bind the preview and sealed draft: %v", err)
		}
		next := fmt.Sprintf("/api/v1/agent/tasks/next?next_sequence=%d&install=xray-official-v1&xray_config=v1&xray_plan=v1&xray_protocols=v1&xray_routing=v1&xray_public=v1&xray_trojan_tls=v1&xray_panel_inbounds=v1", issued.Sequence)
		expect(client.request(http.MethodGet, next, nil, true), http.StatusNoContent)
		expect(client.request(http.MethodGet, next+"&xray_panel_multi_client=v1", nil, true), http.StatusNoContent)
		expect(client.request(http.MethodGet, next+"&xray_panel_trojan=v1", nil, true), http.StatusNoContent)
		next += "&xray_panel_trojan=v1&xray_panel_multi_client=v1"
		expect(client.request(http.MethodGet, next, nil, true), http.StatusNoContent)
		next += "&xray_panel_statistics=v1"
		expect(client.request(http.MethodGet, next, nil, true), http.StatusNoContent)
		next += "&xray_panel_multi_route=v1"
		expect(client.request(http.MethodGet, next, nil, true), http.StatusOK)
		result, err := json.Marshal(lifecycleauth.InstallResult{Outcome: "SUCCEEDED", Version: newer.Version, SHA256: newer.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		expect(client.request(http.MethodPost, "/api/v1/agent/tasks/ack", taskAckRequest{TaskID: applyDirect.TaskID, Sequence: issued.Sequence,
			StatusVersion: 1, Status: "SUCCEEDED", Result: result}, true), http.StatusNoContent)
		direct.Applied, direct.AppliedNetwork, direct.Config, direct.ConfigRevision = &config.Inbounds, config.Network, direct.Candidate, issued.Sequence
		direct.PanelTLS = &config.Panel.TLS.Trust
		direct.StatisticsActive = true
		heartbeat(&direct)
		reportStats := func(sample xraytraffic.Sample) *httptest.ResponseRecorder {
			return client.request(http.MethodPost, "/api/v1/agent/heartbeat", map[string]any{
				"node_id": client.nodeID, "inventory": lifecycleauth.NodeInventory{Architecture: "amd64", Xray: &direct},
				"xray_traffic": sample,
			}, true)
		}
		sample := xraytraffic.Sample{Revision: issued.Sequence, Epoch: strings.Repeat("a", 64), At: time.Now().UnixMilli(),
			Counters: map[string]xraytraffic.Bytes{"user:denied": {Up: 100, Down: 200}}}
		expect(reportStats(sample), http.StatusBadRequest)
		sample.Counters = map[string]xraytraffic.Bytes{"user:alice": {Up: 10, Down: 20}}
		expect(reportStats(sample), http.StatusOK)
		expect(reportStats(sample), http.StatusOK)
		trafficReply := admin(http.MethodGet, nil, "")
		expect(trafficReply, http.StatusOK)
		if !strings.Contains(trafficReply.Body.String(), `"user:alice":{"up":10,"down":20}`) ||
			!strings.Contains(trafficReply.Body.String(), `"user_statistics":"SAMPLED"`) ||
			!strings.Contains(trafficReply.Body.String(), `"exact_quota":"UNSUPPORTED"`) {
			t.Fatal("sample retry changed observed bytes or enabled exact quotas")
		}
		resetBody := map[string]any{"key": "user:alice", "revision": issued.Sequence, "sampled_at": sample.At,
			"expected": sample.Counters["user:alice"]}
		resetURL := "https://panel.example.test" + path + "/traffic/reset"
		expect(subscriptionAdmin(http.MethodPost, resetURL, "", resetBody), http.StatusForbidden)
		expect(subscriptionAdmin(http.MethodPost, resetURL, client.csrf, resetBody), http.StatusOK)
		expect(subscriptionAdmin(http.MethodPost, resetURL, client.csrf, resetBody), http.StatusConflict)
		sample.At++
		sample.Counters["user:alice"] = xraytraffic.Bytes{Up: 13, Down: 24}
		expect(reportStats(sample), http.StatusOK)
		trafficReply = admin(http.MethodGet, nil, "")
		expect(trafficReply, http.StatusOK)
		if !strings.Contains(trafficReply.Body.String(), `"user:alice":{"up":3,"down":4}`) {
			t.Fatal("traffic reset failed to retain the Xray sampling baseline")
		}
		reportedTrust := func() *xrayconfig.TrojanTrust {
			r := admin(http.MethodGet, nil, "")
			expect(r, http.StatusOK)
			var response struct {
				Trust *xrayconfig.TrojanTrust `json:"panel_trust"`
			}
			if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			return response.Trust
		}
		if trust := reportedTrust(); trust == nil || *trust != config.Panel.TLS.Trust {
			t.Fatal("panel withheld the signed, applied TLS certificate")
		}
		subscriptionURL := "https://panel.example.test" + path + "/subscriptions"
		response := requestAsAdmin(t, s.Handler(), http.MethodGet, subscriptionURL, nil, "test-session-token", "")
		expect(response, http.StatusOK)
		if !strings.Contains(response.Body.String(), `"username":"alice","eligible":true`) {
			t.Fatal("panel-managed inbound was unavailable for single-node subscription")
		}
		entries := fetch(aggregateURL, pendingShare.Subscription.Token, "")
		expect(entries, http.StatusOK)
		var subscribed struct{ Entries []clientSubscriptionEntry }
		if err := json.Unmarshal(entries.Body.Bytes(), &subscribed); err != nil || len(subscribed.Entries) != 2 ||
			!strings.Contains(entries.Body.String(), `"public_endpoints"`) || !strings.Contains(entries.Body.String(), config.Panel.TLS.Trust.SHA256) {
			t.Fatalf("aggregate did not include the verified public endpoint and legacy binding: %v", err)
		}
		activeShare := share()
		if len(activeShare.Inbounds) != 2 {
			t.Fatal("applied panel inbound did not receive a share")
		}
		var panelLink string
		for _, entry := range activeShare.Inbounds {
			if entry.XrayBinding == published {
				panelLink = entry.Token
			}
		}
		expect(fetch(aggregateURL, panelLink, ""), http.StatusOK)
		alternative := testTrojanTrust(t)
		applied := append(xrayconfig.Plan{}, *direct.Applied...)
		applied[0].TLSCertSHA256 = alternative.SHA256
		direct.PanelTLS, direct.Applied = alternative, &applied
		heartbeat(&direct)
		if reportedTrust() != nil {
			t.Fatal("accepted certificate supplied by inventory in place of signed trust")
		}
		expect(fetch(aggregateURL, panelLink, ""), http.StatusNotFound)
		direct.PanelTLS, direct.Applied = &config.Panel.TLS.Trust, &config.Inbounds
		heartbeat(&direct)
		rotationRequest := map[string]any{"node_id": client.nodeID, "port": 1080, "revision": 4}
		const rotationPath = "/customer/credential"
		expect(subscriptionAdmin(http.MethodPost, clientsURL+rotationPath, "", rotationRequest), http.StatusForbidden)
		rotate := central(http.MethodPost, rotationPath, rotationRequest)
		expect(rotate, http.StatusOK)
		var delivery issuedClientShare
		if err := json.Unmarshal(rotate.Body.Bytes(), &delivery); err != nil || delivery.Token == "" ||
			delivery.ExpiresAt > time.Now().Add(xrayCredentialDeliveryLifetime).Unix() {
			t.Fatalf("invalid credential delivery link: %v", err)
		}
		expect(central(http.MethodPost, rotationPath, rotationRequest), http.StatusConflict)
		expect(fetch(aggregateURL, delivery.Token, ""), http.StatusNotFound)
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		rotated, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || rotated.Panel.Credentials[0] == config.Panel.Credentials[0] ||
			rotated.Panel.Credentials[1] != config.Panel.Credentials[1] {
			t.Fatalf("rotation did not change only the selected encrypted credential: %v", err)
		}
		rendered, candidate, err := rotated.RenderPanel(private)
		if err != nil {
			t.Fatal(err)
		}
		direct.Candidate, direct.Preview = candidate, xrayconfig.PlanDigest(registered.XrayDraft)
		heartbeat(&direct)
		applyRotated := applyDirect
		applyRotated.TaskID, applyRotated.State = "panel-credential-fixture-12345", options()
		applyRotated.MFACode = fmtCode(totpAt(totpKey, time.Now().Unix()/30))
		expect(admin(http.MethodPost, applyRotated, client.csrf), http.StatusCreated)
		sequence := issued.Sequence + 1
		expect(client.request(http.MethodGet, strings.Replace(next, fmt.Sprintf("next_sequence=%d", issued.Sequence),
			fmt.Sprintf("next_sequence=%d", sequence), 1), nil, true), http.StatusOK)
		expect(client.request(http.MethodPost, "/api/v1/agent/tasks/ack", taskAckRequest{TaskID: applyRotated.TaskID, Sequence: sequence,
			StatusVersion: 1, Status: "SUCCEEDED", Result: result}, true), http.StatusNoContent)
		expect(fetch(aggregateURL, delivery.Token, ""), http.StatusNotFound)
		direct.Applied, direct.AppliedNetwork, direct.Config, direct.ConfigRevision = &rotated.Inbounds, rotated.Network, candidate, sequence
		heartbeat(&direct)
		redeemed := fetch(aggregateURL, delivery.Token, "")
		expect(redeemed, http.StatusOK)
		var delivered struct {
			Credential string                    `json:"credential"`
			Entries    []clientSubscriptionEntry `json:"entries"`
		}
		if err := json.Unmarshal(redeemed.Body.Bytes(), &delivered); err != nil || len(delivered.Entries) != 1 ||
			delivered.Entries[0].NodeID != client.nodeID || delivered.Credential == credential || delivered.Credential == "" ||
			!strings.Contains(string(rendered), delivered.Credential) || redeemed.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("delivery did not return the credential in the exact applied inbound: %v", err)
		}
		ordinaryShare := fetch(aggregateURL, panelLink, "")
		expect(ordinaryShare, http.StatusOK)
		if strings.Contains(ordinaryShare.Body.String(), delivered.Credential) || strings.Contains(rotate.Body.String(), delivered.Credential) {
			t.Fatal("credential leaked into a regular share or the admin response")
		}
		if err := s.store.View(func(st store.State) error {
			raw, err := json.Marshal(st)
			if err != nil {
				return err
			}
			if strings.Contains(string(raw), delivered.Credential) || strings.Contains(string(raw), delivery.Token) {
				return fmt.Errorf("plaintext credential or delivery token persisted")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		expect(bind(5, legacy), http.StatusOK)
		expect(fetch(aggregateURL, panelLink, ""), http.StatusNotFound)
		expect(fetch(aggregateURL, delivery.Token, ""), http.StatusNotFound)
		entries = fetch(aggregateURL, activeShare.Subscription.Token, "")
		expect(entries, http.StatusOK)
		if strings.Contains(entries.Body.String(), `"public_endpoints"`) {
			t.Fatal("removed panel binding remained in the aggregate before node apply")
		}
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		revoked, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || revoked.Panel == nil || len(revoked.Inbounds) != 1 ||
			!slices.Equal(revoked.Inbounds[0].Users, []string{"bob"}) ||
			!slices.Equal(revoked.Panel.Credentials, rotated.Panel.Credentials[1:]) ||
			!reflect.DeepEqual(revoked.Panel.TLS, rotated.Panel.TLS) || !reflect.DeepEqual(revoked.Network, network) {
			t.Fatalf("unbind did not preserve the other client and inbound routing: %v", err)
		}
		expect(central(http.MethodPost, "", map[string]string{"username": "charlie"}), http.StatusCreated)
		generated := store.XrayBinding{NodeID: client.nodeID, Port: 1080, Credential: "charlie"}
		bindGenerated := map[string]any{"revision": 1, "bindings": []store.XrayBinding{generated}, "generate": []store.XrayBinding{generated}}
		created := central(http.MethodPut, "/charlie/bindings", bindGenerated)
		expect(created, http.StatusOK)
		var added struct {
			Deliveries []issuedBindingShare `json:"deliveries"`
		}
		if err := json.Unmarshal(created.Body.Bytes(), &added); err != nil || len(added.Deliveries) != 1 ||
			added.Deliveries[0].XrayBinding != generated || created.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("missing initial credential delivery: %v", err)
		}
		replay := central(http.MethodPut, "/charlie/bindings", bindGenerated)
		expect(replay, http.StatusOK)
		if strings.Contains(replay.Body.String(), "deliveries") {
			t.Fatal("replayed binding generated a second credential")
		}
		expect(fetch(aggregateURL, added.Deliveries[0].Token, ""), http.StatusNotFound)
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		extended, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || !slices.Equal(extended.Inbounds[0].Users, []string{"bob", "charlie"}) ||
			extended.Panel.Credentials[0] != revoked.Panel.Credentials[0] {
			t.Fatalf("adding a client altered another credential: %v", err)
		}
		expect(central(http.MethodPost, "/charlie/delete", map[string]any{"revision": 1}), http.StatusConflict)
		expect(central(http.MethodPost, "/charlie/delete", map[string]any{"revision": 2}), http.StatusOK)
		expect(fetch(aggregateURL, added.Deliveries[0].Token, ""), http.StatusNotFound)
		registered, err = s.store.NodeByID(t.Context(), client.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		deleted, err := xrayconfig.ParseConfiguration(registered.XrayDraft)
		if err != nil || !slices.Equal(deleted.Inbounds[0].Users, []string{"bob"}) ||
			!reflect.DeepEqual(deleted.Network, network) {
			t.Fatalf("client deletion changed another user or routes: %v", err)
		}
	})
	if err := s.ReconcileTaskRuntime(); err != nil {
		t.Fatal(err)
	}
}
