package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/apiasset"
	"github.com/kingmoat/kingmoat/internal/configcenter"
	"github.com/kingmoat/kingmoat/internal/stages"
)

// statusServer builds an RBAC console with the given status-visible options,
// logged in as the seeded admin.
func statusServer(t *testing.T, mutate func(*Options)) (*httptest.Server, *http.Client) {
	t.Helper()
	hash := "$argon2id$v=19$m=65536,t=3,p=4$" +
		mustB64([]byte("0123456789abcdef")) + "$" + mustArgonHash("hunter2")
	center, err := configcenter.Open(filepath.Join(t.TempDir(), "status.db"), seedCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { center.Close() })
	seedStoreAdmin(t, center, hash)
	opts := Options{SkipBootstrap: true, Center: center, Auth: NewAuth(hash)}
	if mutate != nil {
		mutate(&opts)
	}
	srv := New(opts)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	body := mustJSON(t, map[string]string{"username": "admin", "password": "hunter2"})
	resp, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: HTTP %d", resp.StatusCode)
	}
	return ts, &http.Client{Transport: roundTripperWithCookie{cookie: resp.Cookies()[0]}}
}

func TestStatusReportsEffectiveAuditDir(t *testing.T) {
	ts, client := statusServer(t, func(o *Options) {
		o.EffectiveAuditDir = func() string { return `/var/lib/kingmoatwaf/logs` }
	})
	resp, err := client.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if v, ok := out["effective_audit_dir"].(string); !ok || v != `/var/lib/kingmoatwaf/logs` {
		t.Fatalf("effective_audit_dir = %v, want the resolved audit dir", out["effective_audit_dir"])
	}
}

func TestStatusOmitsEffectiveAuditDirWhenUnknown(t *testing.T) {
	ts, client := statusServer(t, nil)
	resp, err := client.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["effective_audit_dir"]; ok {
		t.Fatalf("effective_audit_dir should be omitted when unknown, got %v", out["effective_audit_dir"])
	}
}

func TestDisableStateExplicitEmptyEnvelope(t *testing.T) {
	ts, client := statusServer(t, func(o *Options) {
		o.DisableStateFn = func() *stages.StageDisableRegistry { return nil }
	})
	resp, err := client.Get(ts.URL + "/api/policy/disable-state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"total": 0`) && !strings.Contains(string(body), `"total":0`) {
		t.Fatalf("disable-state = %s, want an explicit envelope with total 0", body)
	}
	if strings.Contains(string(body), "null") {
		t.Fatalf("disable-state = %s, want no bare null", body)
	}
}

func TestExceptionListEmptyIsArray(t *testing.T) {
	ts, client := statusServer(t, nil)
	resp, err := client.Get(ts.URL + "/api/policy/exceptions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "null" || strings.Contains(trimmed, `"result":null`) || strings.Contains(trimmed, `"result": null`) {
		t.Fatalf("exceptions = %s, want []", trimmed)
	}
	if trimmed != "[]" && !strings.Contains(trimmed, `"result": []`) && !strings.Contains(trimmed, `"result":[]`) {
		t.Fatalf("exceptions = %s, want an empty JSON array", trimmed)
	}
}

func TestRiskListCarriesLastScanAt(t *testing.T) {
	store, err := apiasset.Open(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ts, client := statusServer(t, func(o *Options) {
		o.Assets = &AssetsOptions{Store: store}
	})
	resp, err := client.Get(ts.URL + "/api/risks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("risks body: %v", err)
	}
	if v, ok := out["last_scan_at"]; !ok {
		t.Fatalf("risks = %v, want a last_scan_at field (null when never scanned)", out)
	} else if v != nil {
		t.Fatalf("last_scan_at = %v, want null for a never-scanned store", v)
	}
}
