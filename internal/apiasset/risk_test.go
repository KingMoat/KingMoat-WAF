package apiasset

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRiskScanProducesFindings(t *testing.T) {
	store, err := Open(t.TempDir() + "/risk.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	old := time.Now().AddDate(0, 0, -60)
	// R2 seed: credential-heavy API hammered anonymously.
	if err := store.UpsertAsset(&Asset{
		Site: "s.local", Method: "GET", NormPath: "/api/v1/orders",
		AuthedRatio: 0.8, AnonOK: 50, Hits: 100,
		StatusDist: map[string]int{"2xx": 90},
		FirstSeen:  old, LastSeen: time.Now(),
	}, false); err != nil {
		t.Fatal(err)
	}
	// R5 seed: stale asset.
	if err := store.UpsertAsset(&Asset{
		Site: "s.local", Method: "GET", NormPath: "/api/legacy",
		Hits: 10, FirstSeen: old, LastSeen: old,
	}, false); err != nil {
		t.Fatal(err)
	}
	// R7 seed: plaintext sensitive params.
	if err := store.UpsertAsset(&Asset{
		Site: "http.local", Method: "POST", NormPath: "/api/login",
		Hits: 30, Sensitive: map[string]int{"password": 30},
		FirstSeen: old, LastSeen: time.Now(),
	}, false); err != nil {
		t.Fatal(err)
	}
	// R1 seed: respfilter detections.
	for i := 0; i < 12; i++ {
		if err := store.UpsertRespFilterHit("s.local", "/api/v1/users", "phone", 1); err != nil {
			t.Fatal(err)
		}
	}

	var rawSens string
	_ = store.db.QueryRow("SELECT sensitive_json FROM api_assets WHERE norm_path='/api/login'").Scan(&rawSens)
	t.Logf("raw sensitive_json=%q", rawSens)
	dbgAssets, _, _ := store.ListAssets("", "", "", "", false, 0, 100)
	for _, da := range dbgAssets {
		t.Logf("asset %s %s sens=%v", da.Method, da.NormPath, da.Sensitive)
	}
	e := NewEngine(store, &RisksConfig{ZombieDays: 30}, nil, nil)
	n, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("new findings = %d, want >= 4", n)
	}
	risks, total, err := store.ListRisks("open", "", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total < 4 {
		t.Fatalf("open risks = %d", total)
	}
	kinds := map[string]bool{}
	for _, r := range risks {
		kinds[r.Kind] = true
		t.Logf("risk kind=%s level=%s ref=%s", r.Kind, r.Level, r.AssetRef)
		if r.ID == "" || r.Status != "open" {
			t.Fatalf("bad risk: %+v", r)
		}
	}
	for _, want := range []string{RiskSensitiveExposure, RiskUnauthorized, RiskZombieAPI, RiskPlaintextSecret} {
		if !kinds[want] {
			t.Errorf("missing risk kind %q; got %v", want, kinds)
		}
	}

	// Re-scan must not create duplicates (count refresh instead).
	n2, err := e.RunScan()
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Fatalf("rescan created %d new findings, want 0", n2)
	}

	// Status machine.
	if err := store.SetRiskStatus(risks[0].ID, "ignored"); err != nil {
		t.Fatal(err)
	}
	if _, total2, err := store.ListRisks("ignored", "", "", 0, 10); err != nil || total2 != 1 {
		t.Fatalf("ignored list = %d, %v", total2, err)
	}
}

func TestWebhookNotifierPayload(t *testing.T) {
	var got string
	srv := startTestSrv(t, func(body []byte) { got = string(body) })
	n := NewWebhookNotifier(srv.URL, nil)
	if err := n.NotifyRisk(&Risk{ID: "r1", Kind: RiskBruteForce, Level: "high", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("webhook body empty")
	}
	// Empty URL is a no-op.
	if err := NewWebhookNotifier("", nil).NotifyRisk(&Risk{ID: "r2"}); err != nil {
		t.Fatal(err)
	}
}

func startTestSrv(t *testing.T, onBody func([]byte)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		onBody(b)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv
}
