package apiasset

import (
	"testing"
	"time"
)

// TestSiteListExcludesEmptySites pins the N2 fix: rows with an empty site
// (pre-guard writer artifact) never surface in the site inventory, and the
// Open() purge removes the stale rows so risk rules stop seeing them too.
func TestSiteListExcludesEmptySites(t *testing.T) {
	dbPath := t.TempDir() + "/sites.db"
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -1)
	seed := []*Asset{
		{Site: "a.local", Method: "GET", NormPath: "/x", Hits: 9, FirstSeen: old, LastSeen: old},
		{Site: "b.local", Method: "GET", NormPath: "/y", Hits: 9, FirstSeen: old, LastSeen: old},
	}
	for _, a := range seed {
		if err := store.UpsertAsset(a, false); err != nil {
			t.Fatal(err)
		}
	}
	// A legacy empty-site row written directly (bypassing the writer guard,
	// as the pre-fix collector could).
	if _, err := store.db.Exec(`INSERT INTO api_assets (site, method, norm_path, hits, first_seen, last_seen)
		VALUES('', 'GET', '/ghost', 9, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	sites, err := store.SiteList()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 || sites[0] != "a.local" || sites[1] != "b.local" {
		t.Fatalf("SiteList = %v, want [a.local b.local]", sites)
	}

	// Reopen: the purge must drop the empty-site row for good (risk-rule
	// inputs and the inventory stay clean across restarts).
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	sites2, err := store2.SiteList()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites2) != 2 {
		t.Fatalf("SiteList after reopen = %v, want the two real sites", sites2)
	}
	var ghosts int
	if err := store2.db.QueryRow(`SELECT count(*) FROM api_assets WHERE site = ''`).Scan(&ghosts); err != nil {
		t.Fatal(err)
	}
	if ghosts != 0 {
		t.Fatalf("empty-site rows survived the Open() purge: %d", ghosts)
	}
}

// TestEmptySiteWritesRejected pins the writer-side guard: UpsertAsset and
// UpsertRespFilterHit refuse empty sites; the collector drops unknown-site
// ticks and respfilter hits before they ever reach the store.
func TestEmptySiteWritesRejected(t *testing.T) {
	store, err := Open(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old := time.Now().AddDate(0, 0, -1)
	if err := store.UpsertAsset(&Asset{Site: "", Method: "GET", NormPath: "/x", Hits: 9, FirstSeen: old, LastSeen: old}, false); err == nil {
		t.Fatal("UpsertAsset with an empty site must fail")
	}
	if err := store.UpsertRespFilterHit("", "/x", "phone", 1); err == nil {
		t.Fatal("UpsertRespFilterHit with an empty site must fail")
	}

	col := NewCollector(store, 1, nil)
	t.Cleanup(func() { _ = col.Close() })
	col.Submit(AccessTick{Site: "", Method: "GET", Path: "/ghost", TS: old})
	col.RespFilterHit("", "/ghost", "phone")
	col.flush()
	var n int
	if err := store.db.QueryRow(`SELECT count(*) FROM api_assets WHERE site = ''`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("empty-site assets after flush = %d, %v", n, err)
	}
	if err := store.db.QueryRow(`SELECT count(*) FROM respfilter_hits WHERE site = ''`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("empty-site respfilter rows after flush = %d, %v", n, err)
	}
}

// TestLastScanAt pins the N6 scan timestamp: unset until the first
// Engine.RunScan completes, then persisted across reopen.
func TestLastScanAt(t *testing.T) {
	dbPath := t.TempDir() + "/scan.db"
	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.LastScanAt(); ok {
		t.Fatal("LastScanAt must report unset before the first scan")
	}

	e := NewEngine(store, nil, nil, nil)
	before := time.Now().Add(-time.Second)
	if _, err := e.RunScan(); err != nil {
		t.Fatal(err)
	}
	ts, ok := store.LastScanAt()
	if !ok {
		t.Fatal("LastScanAt must be set after RunScan")
	}
	if ts.Before(before) || ts.After(time.Now().Add(time.Second)) {
		t.Fatalf("LastScanAt = %v, want within [%v, now]", ts, before)
	}

	// The timestamp survives a reopen (persisted in the asset DB, not the
	// engine, which is rebuilt on hot reloads).
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store2, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	if _, ok := store2.LastScanAt(); !ok {
		t.Fatal("LastScanAt must survive a reopen")
	}
}
