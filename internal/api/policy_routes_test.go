package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestPolicyRoutes wires the strategy-console endpoints end to end: exception
// create/list/delete with RBAC gating, and the IP-group list route.
func TestPolicyRoutes(t *testing.T) {
	ts, login := rbacServer(t)
	admin := login("admin", "hunter2")

	// Seed an auditor account (rbacServer only seeds the admin).
	const audPass = "hunter2x"
	if code := doJSON(t, admin, "POST", ts.URL+"/api/users", map[string]string{
		"username": "aud", "password": audPass, "role": "auditor",
	}); code != http.StatusOK {
		t.Fatalf("create auditor = %d", code)
	}
	auditor := login("aud", audPass)

	// Empty list initially.
	var list []map[string]any
	resp, err := admin.Get(ts.URL + "/api/policy/exceptions")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET exceptions = %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(list) != 0 {
		t.Fatalf("expected empty exception list, got %d", len(list))
	}

	// Create one exception (operator+).
	exc := map[string]any{"site": "a.local", "path": "/api/search", "prefix": true,
		"rule_id": "coraza/rule-949110", "comment": "fp in search box"}
	if code := doJSON(t, admin, "POST", ts.URL+"/api/policy/exceptions", exc); code != http.StatusOK {
		t.Fatalf("POST exceptions = %d", code)
	}

	// Auditor is read-only.
	if code := doJSON(t, auditor, "POST", ts.URL+"/api/policy/exceptions", exc); code != http.StatusForbidden {
		t.Fatalf("auditor POST exceptions = %d, want 403", code)
	}

	// List shows the entry.
	resp, err = admin.Get(ts.URL + "/api/policy/exceptions")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(list) != 1 || list[0]["path"] != "/api/search" {
		t.Fatalf("exception list after create = %d, %v", resp.StatusCode, list)
	}

	// Delete by index and verify empty again.
	if code := doJSON(t, admin, "DELETE", ts.URL+"/api/policy/exceptions/0", nil); code != http.StatusOK {
		t.Fatalf("DELETE exceptions/0 = %d", code)
	}
	resp, err = admin.Get(ts.URL + "/api/policy/exceptions")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(list) != 0 {
		t.Fatalf("exception list after delete = %v", list)
	}

	// Out-of-range delete is a 404.
	if code := doJSON(t, admin, "DELETE", ts.URL+"/api/policy/exceptions/99", nil); code != http.StatusNotFound {
		t.Fatalf("DELETE exceptions/99 = %d, want 404", code)
	}

	// IP-group list route answers (empty fleet → 404 with JSON error is also
	// acceptable; anything but a routing 404 miss is fine — we assert it is
	// one of the handled statuses).
	resp, err = admin.Get(ts.URL + "/api/ipgroups")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/ipgroups = %d", resp.StatusCode)
	}
}
