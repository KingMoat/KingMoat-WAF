package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// The public Gitee releases feed (the repository is public; downloads and
// feed reads are anonymous — no credentials exist on this path). Facts
// verified in T-00:
//   - the feed ordering is NOT newest-first (a per_page=2 query returned
//     old releases), so a full page is fetched and sorted locally;
//   - release assets follow kingmoat_v<ver>_<os>_<arch>.(tar.gz|zip) plus
//     checksums.txt; Gitee also auto-attaches source archives, which are
//     never matched.
const (
	giteeAPIBase    = "https://gitee.com"
	giteeOwner      = "kingmoat"
	giteeRepo       = "kingmoat"
	releasesPerPage = 20 // one page covers the release count for the foreseeable future
)

// Release is the subset of the Gitee release object this package consumes.
type Release struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	Draft       bool    `json:"draft"`
	Prerelease  bool    `json:"prerelease"` // kept: the release channel is all-beta
	CreatedAt   string  `json:"created_at"`
	PublishedAt string  `json:"published_at"`
	Assets      []Asset `json:"assets"`
}

// Asset is one downloadable release attachment.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// fetchReleases pulls one page of the releases feed. The context deadline
// is bounded here so both Check() and the detecting stage are protected
// regardless of the caller's context.
func (s *Service) fetchReleases(ctx context.Context) ([]Release, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	endpoint := s.apiBase + "/api/v5/repos/" + giteeOwner + "/" + giteeRepo +
		"/releases?per_page=" + strconv.Itoa(releasesPerPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("构造版本查询请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询发布列表失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询发布列表失败: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("读取发布列表失败: %w", err)
	}
	var releases []Release
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("解析发布列表失败: %w", err)
	}
	return releases, nil
}

// latestRelease picks the newest non-draft release by semver. Feed ordering
// is untrusted (T-00), so the whole page is compared; tags that do not
// parse as semver are skipped; prereleases participate (single beta channel).
func latestRelease(releases []Release) (*Release, error) {
	var best *Release
	bestV := ""
	for i := range releases {
		r := &releases[i]
		if r.Draft {
			continue
		}
		v := normalizeVersion(r.TagName)
		if !semver.IsValid(v) {
			continue
		}
		if best == nil || semver.Compare(v, bestV) > 0 {
			best, bestV = r, v
		}
	}
	if best == nil {
		return nil, errors.New("发布列表中没有可识别的版本")
	}
	return best, nil
}

// findRelease locates the release with the given version tag.
func findRelease(releases []Release, version string) (*Release, error) {
	want := normalizeVersion(version)
	for i := range releases {
		if normalizeVersion(releases[i].TagName) == want {
			return &releases[i], nil
		}
	}
	return nil, fmt.Errorf("目标版本 %s 不在发布列表中", version)
}

// normalizeVersion makes a version string comparable by x/mod/semver:
// trimmed with a lowercase "v" prefix enforced. Release tags (v0.7.8-beta)
// and the ldflags-injected main.version share the format; the prefix is
// added defensively for bare "0.7.8" input.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		return "v" + v[1:]
	}
	return "v" + v
}

// maxNotesRunes bounds the release-notes excerpt surfaced by Check (the UI
// shows the excerpt plus a link to the full notes).
const maxNotesRunes = 500

// truncateNotes trims the release body to maxNotesRunes runes.
func truncateNotes(body string) string {
	body = strings.TrimSpace(body)
	runes := []rune(body)
	if len(runes) <= maxNotesRunes {
		return body
	}
	return strings.TrimSpace(string(runes[:maxNotesRunes])) + "…"
}

// AssetForPlatform finds the release attachment matching the given platform
// (T-00 naming). Only assets following the kingmoat_ naming convention are
// matched, so Gitee's auto-generated source archives can never be picked.
func AssetForPlatform(rel *Release, goos, goarch string) (*Asset, error) {
	name, ok := platformArchiveName(normalizeVersion(rel.TagName), goos, goarch)
	if !ok {
		return nil, fmt.Errorf("当前平台 %s/%s 不提供在线升级包", goos, goarch)
	}
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("发布 %s 未提供 %s/%s 的升级包（期望附件 %s）", rel.TagName, goos, goarch, name)
}

// platformArchiveName returns the release-asset filename for the platform
// and whether the platform ships self-upgrade packages at all.
func platformArchiveName(version, goos, goarch string) (string, bool) {
	switch {
	case goos == "linux" && goarch == "amd64":
		return "kingmoat_" + version + "_linux_amd64.tar.gz", true
	case goos == "linux" && goarch == "arm64":
		return "kingmoat_" + version + "_linux_arm64.tar.gz", true
	case goos == "windows" && goarch == "amd64":
		return "kingmoat_" + version + "_windows_amd64.zip", true
	default:
		return "", false
	}
}
