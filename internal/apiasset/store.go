package apiasset

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Asset is one learned API endpoint (confirmed or candidate).
type Asset struct {
	ID          int64          `json:"id"`
	Site        string         `json:"site"`
	Method      string         `json:"method"`
	NormPath    string         `json:"norm_path"`
	Tags        []string       `json:"tags,omitempty"`
	Hits        int64          `json:"hits"`
	StatusDist  map[string]int `json:"status_dist,omitempty"`
	Params      []string       `json:"params,omitempty"`
	AuthedRatio float64        `json:"authed_ratio"`
	RespCT      map[string]int `json:"resp_ct,omitempty"`
	UATop       map[string]int `json:"ua_top,omitempty"`
	AnonOK      int64          `json:"anon_ok,omitempty"`
	PublicHits  int64          `json:"public_hits,omitempty"`
	AdminPublic int64          `json:"admin_public,omitempty"`
	Sensitive   map[string]int `json:"sensitive,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Ignored     bool           `json:"ignored,omitempty"`
	Candidate   bool           `json:"candidate,omitempty"`
}

// Risk is one observe-only risk finding.
type Risk struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Level     string         `json:"level"` // high | medium | low
	Site      string         `json:"site,omitempty"`
	AssetRef  string         `json:"asset_ref,omitempty"`
	Message   string         `json:"message"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	Status    string         `json:"status"` // open | ignored | resolved
	Count     int            `json:"count"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Store is the apiasset.db access layer (SQLite, modernc pure-Go driver).
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS api_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    method TEXT NOT NULL,
    norm_path TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 0,
    status_dist TEXT NOT NULL DEFAULT '{}',
    params TEXT NOT NULL DEFAULT '[]',
    authed_ratio REAL NOT NULL DEFAULT 0,
    resp_ct TEXT NOT NULL DEFAULT '{}',
    ua_top TEXT NOT NULL DEFAULT '{}',
    anon_ok INTEGER NOT NULL DEFAULT 0,
    public_hits INTEGER NOT NULL DEFAULT 0,
    admin_public INTEGER NOT NULL DEFAULT 0,
    sensitive_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ignored INTEGER NOT NULL DEFAULT 0,
    UNIQUE(site, method, norm_path)
);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON api_assets(last_seen);
CREATE TABLE IF NOT EXISTS api_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    method TEXT NOT NULL,
    norm_path TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 0,
    status_dist TEXT NOT NULL DEFAULT '{}',
    params TEXT NOT NULL DEFAULT '[]',
    authed_ratio REAL NOT NULL DEFAULT 0,
    resp_ct TEXT NOT NULL DEFAULT '{}',
    ua_top TEXT NOT NULL DEFAULT '{}',
    anon_ok INTEGER NOT NULL DEFAULT 0,
    public_hits INTEGER NOT NULL DEFAULT 0,
    admin_public INTEGER NOT NULL DEFAULT 0,
    sensitive_json TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(site, method, norm_path)
);
CREATE TABLE IF NOT EXISTS respfilter_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    norm_path TEXT NOT NULL,
    pattern TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL,
    UNIQUE(site, norm_path, pattern)
);
CREATE INDEX IF NOT EXISTS idx_rfhits_hits ON respfilter_hits(hits);
CREATE TABLE IF NOT EXISTS api_risks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    level TEXT NOT NULL,
    site TEXT NOT NULL DEFAULT '',
    asset_ref TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',
    count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risks_status ON api_risks(status);
`

// Open opens (and initializes) the asset database.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("apiasset: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apiasset: init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func tsFormat(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// UpsertAsset persists one aggregated entry. candidate=true writes to the
// candidates table; once hits reach min_hits the caller promotes it.
func (s *Store) UpsertAsset(a *Asset, candidate bool) error {
	tags, _ := json.Marshal(a.Tags)
	dist, _ := json.Marshal(a.StatusDist)
	params, _ := json.Marshal(a.Params)
	ct, _ := json.Marshal(a.RespCT)
	ua, _ := json.Marshal(a.UATop)
	sens, _ := json.Marshal(a.Sensitive)
	table := "api_assets"
	if candidate {
		table = "api_candidates"
	}
	_, err := s.db.Exec(`INSERT INTO `+table+`
        (site, method, norm_path, tags, hits, status_dist, params, authed_ratio, resp_ct, ua_top,
         anon_ok, public_hits, admin_public, sensitive_json, first_seen, last_seen)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(site, method, norm_path) DO UPDATE SET
            tags=excluded.tags, hits=excluded.hits, status_dist=excluded.status_dist,
            params=excluded.params, authed_ratio=excluded.authed_ratio,
            resp_ct=excluded.resp_ct, ua_top=excluded.ua_top,
            anon_ok=excluded.anon_ok, public_hits=excluded.public_hits,
            admin_public=excluded.admin_public, sensitive_json=excluded.sensitive_json,
            last_seen=excluded.last_seen`,
		a.Site, a.Method, a.NormPath, string(tags), a.Hits, string(dist), string(params),
		a.AuthedRatio, string(ct), string(ua), a.AnonOK, a.PublicHits, a.AdminPublic,
		string(sens), tsFormat(a.FirstSeen), tsFormat(a.LastSeen))
	if err != nil {
		return fmt.Errorf("apiasset: upsert asset: %w", err)
	}
	return nil
}

// PromoteCandidate moves a candidate into the confirmed table.
func (s *Store) PromoteCandidate(site, method, normPath string) (int64, error) {
	row := s.db.QueryRow(`SELECT id, tags, hits, status_dist, params, authed_ratio, resp_ct, ua_top, anon_ok, public_hits, admin_public, sensitive_json, first_seen, last_seen
        FROM api_candidates WHERE site=? AND method=? AND norm_path=?`, site, method, normPath)
	var a Asset
	var tags, dist, params, ct, ua, sens, first, last string
	err := row.Scan(&a.ID, &tags, &a.Hits, &dist, &params, &a.AuthedRatio, &ct, &ua, &a.AnonOK, &a.PublicHits, &a.AdminPublic, &sens, &first, &last)
	if err != nil {
		return 0, err
	}
	_ = json.Unmarshal([]byte(tags), &a.Tags)
	_ = json.Unmarshal([]byte(dist), &a.StatusDist)
	_ = json.Unmarshal([]byte(params), &a.Params)
	_ = json.Unmarshal([]byte(ct), &a.RespCT)
	_ = json.Unmarshal([]byte(ua), &a.UATop)
	_ = json.Unmarshal([]byte(sens), &a.Sensitive)
	a.FirstSeen, _ = time.Parse(time.RFC3339, first)
	a.LastSeen, _ = time.Parse(time.RFC3339, last)
	a.Candidate = false
	if err := s.UpsertAsset(&a, false); err != nil {
		return 0, err
	}
	_, err = s.db.Exec(`DELETE FROM api_candidates WHERE site=? AND method=? AND norm_path=?`, site, method, normPath)
	return a.ID, err
}

// ListAssets returns confirmed assets with optional filters.
func (s *Store) ListAssets(site, method, tag, q string, includeCandidates bool, offset, limit int) ([]Asset, int, error) {
	where, args := assetWhere(site, method, tag, q, false)
	tables := "api_assets a"
	if includeCandidates {
		where2, args2 := assetWhere(site, method, tag, q, true)
		rows, err := s.queryAssets(tables, where, args)
		if err != nil {
			return nil, 0, err
		}
		cands, err := s.queryAssets("api_candidates a", where2, args2)
		if err != nil {
			return nil, 0, err
		}
		all := append(rows, cands...)
		for i := range all {
			all[i].Candidate = i >= len(rows)
		}
		total := len(all)
		if offset < len(all) {
			end := offset + limit
			if end > len(all) {
				end = len(all)
			}
			all = all[offset:end]
		} else {
			all = nil
		}
		return all, total, nil
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM `+tables+" WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.queryAssetsPaged(tables, where, args, offset, limit)
	return rows, total, err
}

func assetWhere(site, method, tag, q string, candidate bool) (string, []any) {
	where := "1=1"
	var args []any
	if site != "" {
		where += " AND a.site = ?"
		args = append(args, site)
	}
	if method != "" {
		where += " AND a.method = ?"
		args = append(args, method)
	}
	if tag != "" {
		where += " AND a.tags LIKE ?"
		args = append(args, "%"+tag+"%")
	}
	if q != "" {
		where += " AND a.norm_path LIKE ?"
		args = append(args, "%"+q+"%")
	}
	return where, args
}

func (s *Store) queryAssets(table, where string, args []any) ([]Asset, error) {
	return s.queryAssetsPaged(table, where, args, 0, 100000)
}

func (s *Store) queryAssetsPaged(table, where string, args []any, offset, limit int) ([]Asset, error) {
	ignoredCol := "ignored"
	if strings.Contains(table, "api_candidates") {
		ignoredCol = "0 AS ignored"
	}
	rows, err := s.db.Query(`SELECT id, site, method, norm_path, tags, hits, status_dist, params,
        authed_ratio, resp_ct, ua_top, anon_ok, public_hits, admin_public, sensitive_json,
        first_seen, last_seen, `+ignoredCol+`
        FROM `+table+` WHERE `+where+` ORDER BY a.last_seen DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var tags, dist, params, ct, ua, sens, first, last string
		var ignored int
		if err := rows.Scan(&a.ID, &a.Site, &a.Method, &a.NormPath, &tags, &a.Hits, &dist, &params,
			&a.AuthedRatio, &ct, &ua, &a.AnonOK, &a.PublicHits, &a.AdminPublic, &sens,
			&first, &last, &ignored); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &a.Tags)
		_ = json.Unmarshal([]byte(dist), &a.StatusDist)
		_ = json.Unmarshal([]byte(params), &a.Params)
		_ = json.Unmarshal([]byte(ct), &a.RespCT)
		_ = json.Unmarshal([]byte(ua), &a.UATop)
		_ = json.Unmarshal([]byte(sens), &a.Sensitive)
		a.FirstSeen, _ = time.Parse(time.RFC3339, first)
		a.LastSeen, _ = time.Parse(time.RFC3339, last)
		a.Ignored = ignored != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAsset fetches one confirmed asset by id.
func (s *Store) GetAsset(id int64) (*Asset, error) {
	rows, err := s.queryAssetsPaged("api_assets a", "a.id = ?", []any{id}, 0, 1)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("apiasset: asset not found")
	}
	return &rows[0], nil
}

// StaleAssets returns confirmed assets untouched for at least days.
func (s *Store) StaleAssets(days int, limit int) ([]Asset, error) {
	cutoff := tsFormat(time.Now().AddDate(0, 0, -days))
	return s.queryAssetsPaged("api_assets a", "a.ignored = 0 AND a.last_seen < ? AND a.last_seen > ?",
		[]any{cutoff, tsFormat(time.Now().AddDate(-2, 0, 0))}, 0, limit)
}

// RecentAdminExports returns confirmed admin/export-class assets first seen
// after the cutoff (shadow-API hint while OpenAPI import is absent).
func (s *Store) RecentAdminExports(cutoff time.Time, limit int) ([]Asset, error) {
	rows, err := s.queryAssetsPaged("api_assets a", "a.ignored = 0 AND a.first_seen >= ?",
		[]any{tsFormat(cutoff)}, 0, limit)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for _, a := range rows {
		for _, t := range a.Tags {
			if t == TagAdmin || t == TagExport {
				out = append(out, a)
				break
			}
		}
	}
	return out, nil
}

// AdminAssets returns confirmed admin-class assets (R6).
func (s *Store) AdminAssets(limit int) ([]Asset, error) {
	rows, err := s.queryAssetsPaged("api_assets a", "a.ignored = 0 AND a.tags LIKE ?",
		[]any{`%"` + TagAdmin + `"%`}, 0, limit)
	return rows, err
}

// UpsertRisk inserts or refreshes a risk finding (count++, updated_at bump).
// It returns true when the risk is newly created (notification hook).
func (s *Store) UpsertRisk(r *Risk) (bool, error) {
	if r.ID == "" {
		return false, errors.New("apiasset: risk id required")
	}
	if r.Status == "" {
		r.Status = "open"
	}
	now := tsFormat(time.Now())
	ev, _ := json.Marshal(r.Evidence)
	var exists int
	_ = s.db.QueryRow(`SELECT 1 FROM api_risks WHERE id=?`, r.ID).Scan(&exists)
	if exists == 1 {
		if _, err := s.db.Exec(`UPDATE api_risks SET level=?, message=?, evidence=?,
            count = count + 1, updated_at=? WHERE id=?`,
			r.Level, r.Message, string(ev), now, r.ID); err != nil {
			return false, fmt.Errorf("apiasset: refresh risk: %w", err)
		}
		return false, nil
	}
	if _, err := s.db.Exec(`INSERT INTO api_risks (id, kind, level, site, asset_ref, message, evidence, status, count, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?,1,?,?)`,
		r.ID, r.Kind, r.Level, r.Site, r.AssetRef, r.Message, string(ev), r.Status, now, now); err != nil {
		return false, fmt.Errorf("apiasset: insert risk: %w", err)
	}
	return true, nil
}

// ListRisks returns risks with optional filters.
func (s *Store) ListRisks(status, level, kind string, offset, limit int) ([]Risk, int, error) {
	where := "1=1"
	var args []any
	if status != "" {
		where += " AND status = ?"
		args = append(args, status)
	}
	if level != "" {
		where += " AND level = ?"
		args = append(args, level)
	}
	if kind != "" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM api_risks WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT id, kind, level, site, asset_ref, message, evidence, status, count, created_at, updated_at
        FROM api_risks WHERE `+where+` ORDER BY updated_at DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Risk
	for rows.Next() {
		var r Risk
		var ev, created, updated string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Level, &r.Site, &r.AssetRef, &r.Message, &ev, &r.Status, &r.Count, &created, &updated); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal([]byte(ev), &r.Evidence)
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// SetRiskStatus updates open/ignored/resolved state.
func (s *Store) SetRiskStatus(id, status string) error {
	if status != "open" && status != "ignored" && status != "resolved" {
		return errors.New("apiasset: invalid risk status")
	}
	_, err := s.db.Exec(`UPDATE api_risks SET status=?, updated_at=? WHERE id=?`, status, tsFormat(time.Now()), id)
	return err
}

// PurgeOldAssets deletes assets and candidates unseen for days.
func (s *Store) PurgeOldAssets(days int) (int64, error) {
	cutoff := tsFormat(time.Now().AddDate(0, 0, -days))
	r1, err := s.db.Exec(`DELETE FROM api_assets WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	r2, err := s.db.Exec(`DELETE FROM api_candidates WHERE last_seen < ?`, cutoff)
	if err != nil {
		return r1.RowsAffected()
	}
	n1, _ := r1.RowsAffected()
	n2, _ := r2.RowsAffected()
	return n1 + n2, nil
}

// IgnoreAsset marks an asset as reviewed-out (stays in the table, excluded
// from risk signals).
func (s *Store) IgnoreAsset(id int64, ignored bool) error {
	v := 0
	if ignored {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE api_assets SET ignored=? WHERE id=?`, v, id)
	return err
}

// SiteList returns distinct sites present in the inventory.
func (s *Store) SiteList() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT site FROM api_assets ORDER BY site`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var site string
		if err := rows.Scan(&site); err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func stringsJSON(v []string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var _ = strings.TrimSpace

// UpsertRespFilterHit accumulates observe-only sensitive-data detections
// (R1 signal source).
func (s *Store) UpsertRespFilterHit(site, normPath, pattern string, n int) error {
	_, err := s.db.Exec(`INSERT INTO respfilter_hits (site, norm_path, pattern, hits, last_seen)
        VALUES(?,?,?,?,?)
        ON CONFLICT(site, norm_path, pattern) DO UPDATE SET
            hits = hits + excluded.hits, last_seen = excluded.last_seen`,
		site, normPath, pattern, n, tsFormat(time.Now()))
	if err != nil {
		return fmt.Errorf("apiasset: upsert respfilter hit: %w", err)
	}
	return nil
}

// HotRespFilterHits returns pattern detections above minHits (R1).
func (s *Store) HotRespFilterHits(minHits int, limit int) ([]Risk, error) {
	rows, err := s.db.Query(`SELECT site, norm_path, pattern, hits, last_seen
        FROM respfilter_hits WHERE hits >= ? ORDER BY hits DESC LIMIT ?`, minHits, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Risk
	for rows.Next() {
		var site, path, pattern, last string
		var hits int
		if err := rows.Scan(&site, &path, &pattern, &hits, &last); err != nil {
			return nil, err
		}
		out = append(out, Risk{
			Kind: "sensitive_exposure", Level: "high", Site: site, AssetRef: path,
			Message:  "API response frequently contains sensitive data matching pattern " + pattern,
			Evidence: map[string]any{"pattern": pattern, "hits": hits, "last_seen": last},
		})
	}
	return out, rows.Err()
}
