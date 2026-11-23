package master

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ACnoway/mcui/internal/artifacttrust"
	"github.com/ACnoway/mcui/internal/corecatalog"
	"github.com/ACnoway/mcui/internal/lifecycleauth"
	"github.com/ACnoway/mcui/internal/store"
	"github.com/ACnoway/mcui/internal/xrayconfig"
)

func TestPanelXraySelectSignDeliverAndConfirm(t *testing.T) {
	testPanelXraySelectSignDeliverAndConfirm(t, nil)
}

func testPanelXraySelectSignDeliverAndConfirm(t *testing.T, checkpoint func(*testing.T, taskTestClient)) {
	client := newTaskTestClient(t)
	s := client.server
	s.EnableSingleAdmin()
	now := time.Now().UTC().Truncate(time.Second)
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
		"panel":              map[string]any{"node_ids": []string{client.nodeID}},
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
	artifact := func(version, arch, fill string) artifacttrust.Artifact {
		t.Helper()
		digest := strings.Repeat(fill, 64)
		filename, err := corecatalog.ExpectedAssetName("xray", version, arch)
		if err != nil {
			t.Fatal(err)
		}
		return artifacttrust.Artifact{Component: "xray", Version: version, Architecture: arch, OS: "linux",
			SHA256: digest, ArtifactID: "xray-manifest-" + arch + "-" + digest, Filename: filename,
			SourceID: "github:XTLS/Xray-core", ArchiveFormat: "zip", BuildOptions: "upstream-prebuilt",
			Length: 1024, ReviewID: "test-review", SignatureStatus: "not-provided"}
	}
	newer := artifact(xrayconfig.Version, "amd64", "b")
	older := artifact("v26.9.0", "amd64", "a")
	other := artifact("v26.11.0", "arm64", "c")
	rawManifest, err := json.Marshal(artifacttrust.Manifest{SchemaVersion: 1, ManifestVersion: 2, ExpiresAt: now.Add(time.Hour),
		Artifacts: []artifacttrust.Artifact{older, other, newer}})
	if err != nil {
		t.Fatal(err)
	}
	releasePub, releaseKey := generate()
	sig := ed25519.Sign(releaseKey, rawManifest)
	current := func(context.Context) (artifacttrust.Manifest, error) {
		return artifacttrust.VerifyManifest(rawManifest, sig, releasePub, time.Now().UTC())
	}
	token := strings.Repeat("k", 36)
	signer, err := lifecycleauth.NewPanelSignerHandler(policy, ledger, key, []byte(token), trustedNow, current)
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
			State    string   `json:"state"`
			Versions []string `json:"versions"`
			Catalog  int64    `json:"catalog_version"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil || response.Catalog != 2 ||
			!reflect.DeepEqual(response.Versions, []string{newer.Version, older.Version}) {
			t.Fatalf("invalid trusted version selection: %s, %v", r.Body, err)
		}
		return response.State
	}
	expect(admin(http.MethodGet, nil, ""), http.StatusConflict)
	heartbeat(&lifecycleauth.XrayInventory{})
	in := panelXrayRequest{TaskID: "install-fixture-1234567890", Operation: "core.install", Version: other.Version,
		CatalogVersion: 2, State: options()}
	expect(admin(http.MethodPost, in, client.csrf), http.StatusBadRequest)
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
	if err != nil || task.Sequence != 1 || task.Architecture != "amd64" || !task.SignedManifest ||
		task.ManifestVersion != 2 || task.SHA256 != newer.SHA256 || task.Version != newer.Version {
		t.Fatalf("incorrect signed install: %+v %v", task, err)
	}
	if _, err := s.verifyStoredXrayTask(record.Raw, true); err != nil {
		t.Fatal(err)
	}
	complete := func(id string, sequence int64, release artifacttrust.Artifact) {
		t.Helper()
		next := fmt.Sprintf("/api/v1/agent/tasks/next?next_sequence=%d&install=xray-manifest-v1&install_reconciliation=v1&xray_control=v1&xray_change=v1&xray_config=v1&xray_plan=v1", sequence)
		expect(client.request(http.MethodGet, next, nil, true), http.StatusOK)
		result, err := json.Marshal(lifecycleauth.InstallResult{Outcome: "SUCCEEDED", Version: release.Version, SHA256: release.SHA256})
		if err != nil {
			t.Fatal(err)
		}
		expect(client.request(http.MethodPost, "/api/v1/agent/tasks/ack", taskAckRequest{TaskID: id, Sequence: sequence, StatusVersion: 1,
			Status: "SUCCEEDED", Result: result}, true), http.StatusNoContent)
	}
	complete(in.TaskID, 1, newer)
	heartbeat(&lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256, Running: true})
	change := panelXrayRequest{TaskID: "downgrade-fixture-1234567890", Operation: "core.downgrade", Version: older.Version,
		CatalogVersion: 2, State: options()}
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
		CatalogVersion: 2, State: options()}
	expect(admin(http.MethodPost, upgrade, client.csrf), http.StatusCreated)
	complete(upgrade.TaskID, 3, newer)
	config := xrayconfig.Reference{Port: 1080, SHA256: strings.Repeat("d", 64), Size: 350}
	node := lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256, Running: true, Candidate: config}
	heartbeat(&node)
	apply := panelXrayRequest{TaskID: "config-fixture-1234567890", Operation: xrayconfig.Operation, Version: newer.Version,
		CatalogVersion: 2, State: options(), Confirm: xrayconfig.Operation}
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
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=4&install=xray-manifest-v1", nil, true), http.StatusNoContent)
	complete(apply.TaskID, 4, newer)

	node.PlanSupported, node.Candidate = true, xrayconfig.Reference{}
	node.Catalog = &xrayconfig.Catalog{Ports: []int{1080, 1081}, Users: []string{"alice", "bob"}}
	node.Config, node.ConfigRevision = config, 4
	heartbeat(&node)
	draftPath := "https://panel.example.test" + path + "/draft"
	plan := xrayconfig.Plan{{Port: 1081, Users: []string{"alice", "bob"}}}
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
	body["state"], body["plan"] = previous, plan
	expect(save(draftPath, client.csrf), http.StatusOK) // Lost-response retry.
	managed := apply
	managed.TaskID = "managed-fixture-1234567890"
	managed.State, managed.MFACode = options(), fmtCode(totpAt(totpKey, time.Now().Unix()/30))
	expect(admin(http.MethodPost, managed, client.csrf), http.StatusConflict)
	node.Candidate = xrayconfig.Reference{Port: 1081, SHA256: strings.Repeat("e", 64), Size: 420}
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
	expect(client.request(http.MethodGet, "/api/v1/agent/tasks/next?next_sequence=5&install=xray-manifest-v1&xray_config=v1", nil, true), http.StatusNoContent)
	complete(managed.TaskID, 5, newer)

	for i, operation := range []string{"core.start", "core.stop", "core.uninstall"} {
		heartbeat(&lifecycleauth.XrayInventory{Version: newer.Version, SHA256: newer.SHA256})
		id := fmt.Sprintf("control-fixture-%010d", i)
		control := panelXrayRequest{TaskID: id, Operation: operation, State: options()}
		if control.dangerous() {
			control.Confirm, control.MFACode = operation, fmtCode(totpAt(totpKey, time.Now().Unix()/30))
		}
		expect(admin(http.MethodPost, control, client.csrf), http.StatusCreated)
		complete(id, int64(i)+6, newer)
	}
	if err := s.ReconcileTaskRuntime(); err != nil {
		t.Fatal(err)
	}
}
