package upgrade

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// maxAssetBytes caps one downloaded file. Enforced twice: a
	// Content-Length pre-check (cheap rejection before transferring) and an
	// io.LimitReader during streaming (servers may skip or lie about the
	// header).
	maxAssetBytes = 200 << 20
	// maxChecksumsBytes caps checksums.txt (a handful of lines; anything
	// larger is bogus and refused before it can be parsed).
	maxChecksumsBytes = 1 << 20
	// checksumsName is the release attachment holding the SHA256 sums
	// (T-00: shipped alongside the platform archives).
	checksumsName = "checksums.txt"
	// serverBinaryName / cliBinaryName are the payload files inside the
	// release archives; both must be present for the replace card.
	serverBinaryName = "kingmoatwaf"
	cliBinaryName    = "kmwafctl"
)

// defaultAllowedHosts restricts download URLs to the release origin. URLs
// only ever come from the Gitee releases feed; the allowlist is the second
// guard against a tampered feed pointing at a foreign host. github.com is a
// reserved future fallback source and deliberately not enabled (the Gitee
// mirror does not carry release assets).
var defaultAllowedHosts = []string{"gitee.com"}

// taskDir is the per-task workspace under <dataDir>/upgrade/. Task ids are
// hex generated in-process; the path never incorporates external input.
func (s *Service) taskDir(taskID string) string {
	return filepath.Join(s.baseDir, "upgrade", taskID)
}

// downloadRelease fetches the platform asset plus checksums.txt for rel
// into the task workspace (<dataDir>/upgrade/<task-id>/). Contract: any
// error leaves no artifacts behind.
func (s *Service) downloadRelease(ctx context.Context, t *Task, rel *Release) (string, error) {
	asset, err := AssetForPlatform(rel, s.goos, s.goarch)
	if err != nil {
		return "", err
	}
	sums, err := rel.checksumsAsset()
	if err != nil {
		return "", err
	}
	dir := s.taskDir(t.ID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("创建升级工作目录失败: %w", err)
	}
	name := sanitizeFileName(asset.Name)
	if name == "" {
		os.RemoveAll(dir)
		return "", fmt.Errorf("附件名非法: %q", asset.Name)
	}
	archivePath := filepath.Join(dir, name)
	if _, err := s.downloadFile(ctx, asset.BrowserDownloadURL, archivePath, maxAssetBytes); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if _, err := s.downloadFile(ctx, sums.BrowserDownloadURL, filepath.Join(dir, checksumsName), maxChecksumsBytes); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return archivePath, nil
}

// verifyDownload checks the downloaded archive against the release
// checksums file and unpacks the payload binaries into the task directory.
// A mismatch, a missing checksum entry, or missing payload files fail the
// upgrade and wipe the workspace — nothing downstream ever sees unverified
// bytes.
func (s *Service) verifyDownload(ctx context.Context, t *Task, rel *Release, archivePath string) (string, error) {
	dir := filepath.Dir(archivePath)
	sums, err := parseChecksumsFile(filepath.Join(dir, checksumsName))
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	assetName := filepath.Base(archivePath)
	want, ok := sums[assetName]
	if !ok {
		os.RemoveAll(dir)
		return "", fmt.Errorf("checksums.txt 缺少 %s 的校验条目，已中止升级", assetName)
	}
	if err := verifyFileSHA256(archivePath, want); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := extractArchive(archivePath, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	for _, name := range []string{serverBinaryName, cliBinaryName} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.IsDir() {
			os.RemoveAll(dir)
			return "", fmt.Errorf("升级包内缺少 %s，已中止升级", name)
		}
	}
	return dir, nil
}

// downloadFile streams rawURL into destPath under the download policy:
// HTTPS only, origin allowlist, hard per-file size cap. The policy applies
// to the WHOLE redirect chain, not just the feed-supplied URL: Gitee
// serves attachments through redirects, and a tampered feed (or a
// compromised origin) could otherwise bounce the client to any scheme or
// host - the default redirect policy follows blindly. CheckRedirect
// re-validates every hop (and stops past maxRedirectHops), and the SHA256
// verification remains the integrity backstop regardless of path.
func (s *Service) downloadFile(ctx context.Context, rawURL, destPath string, maxBytes int64) (int64, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, fmt.Errorf("解析下载地址失败: %w", err)
	}
	if err := s.validateDownloadURL(u); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, fmt.Errorf("构造下载请求失败: %w", err)
	}
	// Per-download client copy: same transport (test TLS trust; deadlines
	// ride on the request context) so the redirect gate below is scoped
	// to this download instead of the shared feed client.
	client := *s.httpClient
	client.CheckRedirect = s.redirectCheck()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("下载 %s 失败: %w", u.Host+u.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("下载 %s 失败: HTTP %d", u.Host+u.Path, resp.StatusCode)
	}
	if cl := resp.ContentLength; cl > maxBytes {
		return 0, fmt.Errorf("下载 %s 大小超过上限（%d > %d 字节）", u.Host+u.Path, cl, maxBytes)
	}
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("写入下载文件失败: %w", err)
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := f.Close()
	if copyErr == nil && n > maxBytes {
		copyErr = fmt.Errorf("下载 %s 大小超过上限（%d > %d 字节）", u.Host+u.Path, n, maxBytes)
	}
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(destPath)
		return 0, copyErr
	}
	return n, nil
}

// maxRedirectHops bounds one download's redirect chain - the same
// stop-after-10 the net/http default applies, but with a policy-flavored
// error instead of the generic one. via[0] is the original request, so
// the count includes it.
const maxRedirectHops = 10

// validateDownloadURL enforces the download policy on one URL of the
// download chain - the initial feed-supplied address and every redirect
// hop alike: HTTPS only and origin-allowlisted.
func (s *Service) validateDownloadURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("拒绝非 HTTPS 下载地址: %s", u)
	}
	if !s.hostAllowed(u.Hostname()) {
		return fmt.Errorf("下载地址 %q 不在允许的来源域名列表", u)
	}
	return nil
}

// redirectCheck is the per-hop redirect gate installed as the download
// client's CheckRedirect: every hop must re-satisfy the download policy
// (HTTPS, allowlist) before it is sent, and chains past maxRedirectHops
// are cut. A plain error aborts the chain and surfaces (wrapped in
// url.Error) as the download failure; the client closes the refused
// response body.
func (s *Service) redirectCheck() func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirectHops {
			return fmt.Errorf("重定向超过 %d 跳，中止下载", maxRedirectHops)
		}
		if err := s.validateDownloadURL(req.URL); err != nil {
			return fmt.Errorf("重定向跳转未通过下载策略: %w", err)
		}
		return nil
	}
}

// hostAllowed matches the URL host against the allowlist (exact hostnames,
// case-insensitive, trailing dot tolerated).
func (s *Service) hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range s.allowedHosts {
		if host == strings.ToLower(h) {
			return true
		}
	}
	return false
}

// sanitizeFileName reduces a feed-supplied filename to a bare name: no
// separators, no dot-dot, no absolute paths. Matched asset names are
// strictly patterned already; this is the last-resort guard.
func sanitizeFileName(name string) string {
	name = filepath.Base(path.Base(strings.ReplaceAll(name, "\\", "/")))
	if name == "." || name == ".." || name == "" || name == string(filepath.Separator) {
		return ""
	}
	return name
}

// checksumsAsset locates the checksums.txt attachment of the release. Its
// absence is fatal: verification is mandatory, never skipped.
func (r *Release) checksumsAsset() (*Asset, error) {
	for i := range r.Assets {
		if r.Assets[i].Name == checksumsName {
			return &r.Assets[i], nil
		}
	}
	return nil, fmt.Errorf("发布 %s 未附带 checksums.txt，无法校验升级包完整性", r.TagName)
}

// parseChecksumsFile reads and parses a sha256sum-style sums file.
func parseChecksumsFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 checksums.txt 失败: %w", err)
	}
	return parseChecksums(string(data))
}

// parseChecksums parses "<hex>  <filename>" lines. One or more spaces (and
// an optional "*" binary-mode marker) are tolerated, as are CRLF line
// endings — the release build writes the sums file on Windows.
func parseChecksums(content string) (map[string]string, error) {
	out := map[string]string{}
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("checksums.txt 第 %d 行格式非法", i+1)
		}
		hash := strings.ToLower(fields[0])
		if !isHex64(hash) {
			return nil, fmt.Errorf("checksums.txt 第 %d 行校验值非法", i+1)
		}
		// Filenames containing spaces would break the field split; release
		// asset names never contain spaces (T-00), and such a name simply
		// fails the lookup below — fail-closed either way.
		out[strings.TrimPrefix(fields[1], "*")] = hash
	}
	if len(out) == 0 {
		return nil, errors.New("checksums.txt 为空")
	}
	return out, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// verifyFileSHA256 hashes the file and compares against wantHex
// (case-insensitive; the sums file is lowercase hex).
func verifyFileSHA256(path, wantHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开已下载文件失败: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("计算 SHA256 失败: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantHex) {
		return fmt.Errorf("SHA256 校验不匹配（期望 %s，实际 %s），已拒绝该升级包", wantHex, got)
	}
	return nil
}

// extractArchive unpacks the payload binaries from the verified archive
// into dir. tar.gz and zip are the shipped package formats (T-00).
func extractArchive(archivePath, dir string) error {
	switch {
	case strings.HasSuffix(archivePath, ".tar.gz"), strings.HasSuffix(archivePath, ".tgz"):
		return extractTarGz(archivePath, dir)
	case strings.HasSuffix(archivePath, ".zip"):
		return extractZip(archivePath, dir)
	default:
		return fmt.Errorf("未知升级包格式: %s", filepath.Base(archivePath))
	}
}

func extractTarGz(archivePath, dir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("打开升级包失败: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("读取 gzip 流失败: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 流失败: %w", err)
		}
		if !payloadEntry(hdr.Name) {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("升级包内 %s 不是普通文件", path.Base(hdr.Name))
		}
		if err := writePayload(filepath.Join(dir, path.Base(hdr.Name)), tr, maxAssetBytes); err != nil {
			return err
		}
	}
	return nil
}

func extractZip(archivePath, dir string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("打开 zip 升级包失败: %w", err)
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if !payloadEntry(zf.Name) {
			continue
		}
		if zf.FileInfo().IsDir() || zf.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("升级包内 %s 不是普通文件", path.Base(zf.Name))
		}
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("读取 zip 条目失败: %w", err)
		}
		err = writePayload(filepath.Join(dir, path.Base(zf.Name)), rc, maxAssetBytes)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// payloadEntry reports whether a tar/zip entry is one of the two payload
// binaries. Matching uses the base name only: archives may wrap the
// binaries in a top-level directory, and any "../" trickery reduces to a
// harmless name that cannot match — crafted paths can never escape dir.
func payloadEntry(name string) bool {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	return base == serverBinaryName || base == cliBinaryName
}

// writePayload materializes one payload file with executable permissions
// (zip entries built on Windows carry no exec bits) and the same size cap
// as downloads.
func writePayload(dest string, r io.Reader, maxBytes int64) error {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("写出升级文件失败: %w", err)
	}
	n, copyErr := io.Copy(f, io.LimitReader(r, maxBytes+1))
	closeErr := f.Close()
	if copyErr == nil && n > maxBytes {
		copyErr = errors.New("升级包内文件超出大小上限")
	}
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	return nil
}
