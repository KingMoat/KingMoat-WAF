package upgrade

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testVersion   = "v0.7.9-beta"
	testPayloadA  = "KINGMOAT-SERVER-BYTES"
	testPayloadB  = "kingmoat-cli-bytes"
	testArchiveNm = "kingmoat_" + testVersion + "_linux_amd64.tar.gz"
)

// sha256Hex returns the lowercase hex digest used in checksums files.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// buildTarGz produces an in-memory tar.gz with the given entries.
func buildTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
			ModTime:  time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildZip produces an in-memory zip with the given entries.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sumsFile renders a sha256sum-style sums file (two-space separator).
func sumsFile(pairs map[string][]byte) string {
	var b strings.Builder
	for name, content := range pairs {
		fmt.Fprintf(&b, "%s  %s\n", sha256Hex(content), name)
	}
	return b.String()
}

// assetServer serves GET /<name> from files over TLS (https-only policy
// applies); srv.Client() trusts the test certificate.
func assetServer(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		content, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testServiceOptions wires a service at the asset server: https client that
// trusts the test cert, 127.0.0.1 allowlisted, linux/amd64 platform.
func testServiceOptions(srv *httptest.Server) []Option {
	return []Option{
		WithHTTPClient(srv.Client()),
		WithAllowedHosts([]string{"127.0.0.1"}),
		WithPlatform("linux", "amd64"),
	}
}

// testRelease assembles a release whose assets point at srv.
func testRelease(srv *httptest.Server, withSums bool, extra ...Asset) *Release {
	return testReleaseNamed(srv, testArchiveNm, withSums, extra...)
}

// testReleaseNamed assembles a release with a specific archive asset name.
func testReleaseNamed(srv *httptest.Server, archiveName string, withSums bool, extra ...Asset) *Release {
	assets := []Asset{
		{Name: archiveName, BrowserDownloadURL: srv.URL + "/" + archiveName, Size: 1},
	}
	if withSums {
		assets = append(assets, Asset{Name: checksumsName, BrowserDownloadURL: srv.URL + "/" + checksumsName, Size: 1})
	}
	assets = append(assets, extra...)
	return &Release{TagName: testVersion, Assets: assets}
}

// dirExists reports whether the task workspace is still on disk.
func dirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestAssetForPlatform covers the T-00 asset naming per platform and the
// refusal for platforms without self-upgrade packages.
func TestAssetForPlatform(t *testing.T) {
	rel := &Release{TagName: testVersion, Assets: []Asset{
		{Name: "kingmoat_" + testVersion + "_linux_amd64.tar.gz"},
		{Name: "kingmoat_" + testVersion + "_linux_arm64.tar.gz"},
		{Name: "kingmoat_" + testVersion + "_windows_amd64.zip"},
		{Name: testVersion + ".tar.gz"}, // Gitee source archive
	}}
	cases := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "kingmoat_" + testVersion + "_linux_amd64.tar.gz"},
		{"linux", "arm64", "kingmoat_" + testVersion + "_linux_arm64.tar.gz"},
		{"windows", "amd64", "kingmoat_" + testVersion + "_windows_amd64.zip"},
	}
	for _, tc := range cases {
		asset, err := AssetForPlatform(rel, tc.goos, tc.goarch)
		if err != nil || asset.Name != tc.want {
			t.Fatalf("AssetForPlatform(%s/%s) = %v, %v; want %s", tc.goos, tc.goarch, asset, err, tc.want)
		}
	}
	if _, err := AssetForPlatform(rel, "darwin", "arm64"); err == nil {
		t.Fatal("darwin/arm64 must be unsupported")
	}
	bare := &Release{TagName: testVersion}
	if _, err := AssetForPlatform(bare, "linux", "amd64"); err == nil {
		t.Fatal("release without platform asset must error")
	}
}

// TestDownloadAndVerifyTarGz walks the full download+verify pair against an
// httptest server: both files fetched, SHA256 verified, wrapped-archive
// layout unpacked to the two payload binaries, tolerant sums formatting.
func TestDownloadAndVerifyTarGz(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{
		"kingmoat_" + testVersion + "/kingmoat":     []byte(testPayloadA),
		"kingmoat_" + testVersion + "/kingmoat-cli": []byte(testPayloadB),
	})
	// CRLF + single-space + a comment line: all tolerated.
	sums := "# sha256 sums\r\n" + sha256Hex(archive) + " " + testArchiveNm + "\r\n"
	srv := assetServer(t, map[string][]byte{testArchiveNm: archive, checksumsName: []byte(sums)})
	s := NewService("v0.7.8-beta", t.TempDir(), testServiceOptions(srv)...)

	task := &Task{ID: "tartask0001"}
	archivePath, err := s.downloadRelease(context.Background(), task, testRelease(srv, true))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(archivePath) != s.taskDir(task.ID) {
		t.Fatalf("archive at %s, want inside the task workspace", archivePath)
	}
	dir, err := s.verifyDownload(context.Background(), task, testRelease(srv, true), archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if dir != s.taskDir(task.ID) {
		t.Fatalf("artifact dir = %s, want %s", dir, s.taskDir(task.ID))
	}
	for name, want := range map[string]string{"kingmoat": testPayloadA, "kingmoat-cli": testPayloadB} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("payload %s = %q, %v; want %q", name, got, err, want)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(filepath.Join(dir, name)); fi.Mode().Perm()&0o100 == 0 {
				t.Fatalf("payload %s not executable: %v", name, fi.Mode())
			}
		}
	}
}

// TestDownloadAndVerifyZip covers the windows zip package format.
func TestDownloadAndVerifyZip(t *testing.T) {
	zipName := "kingmoat_" + testVersion + "_windows_amd64.zip"
	archive := buildZip(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	sums := sumsFile(map[string][]byte{zipName: archive})
	srv := assetServer(t, map[string][]byte{zipName: archive, checksumsName: []byte(sums)})
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithHTTPClient(srv.Client()), WithAllowedHosts([]string{"127.0.0.1"}), WithPlatform("windows", "amd64"))

	task := &Task{ID: "ziptask0001"}
	archivePath, err := s.downloadRelease(context.Background(), task, testReleaseNamed(srv, zipName, true))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(archivePath) != zipName {
		t.Fatalf("archive = %s, want %s", archivePath, zipName)
	}
	if _, err := s.verifyDownload(context.Background(), task, testReleaseNamed(srv, zipName, true), archivePath); err != nil {
		t.Fatal(err)
	}
}

// TestChecksumMismatch: a wrong digest fails verification and wipes the
// workspace — nothing survives for the replace stage.
func TestChecksumMismatch(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	// A sums file listing the right name with the wrong digest: SHA256
	// mismatch, fail-closed, workspace wiped.
	badSums := sumsFile(map[string][]byte{testArchiveNm: []byte("not the archive bytes")})
	srv := assetServer(t, map[string][]byte{testArchiveNm: archive, checksumsName: []byte(badSums)})
	s := NewService("v0.7.8-beta", t.TempDir(), testServiceOptions(srv)...)

	task := &Task{ID: "misstask0001"}
	archivePath, err := s.downloadRelease(context.Background(), task, testRelease(srv, true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.verifyDownload(context.Background(), task, testRelease(srv, true), archivePath)
	if err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("verify = %v, want SHA256 mismatch error", err)
	}
	if dirExists(s.taskDir(task.ID)) {
		t.Fatal("task workspace must be wiped after a checksum mismatch")
	}
}

// TestChecksumMissingEntry: a sums file without the asset's entry is
// fail-closed.
func TestChecksumMissingEntry(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{testArchiveNm: archive, checksumsName: []byte("")})
	s := NewService("v0.7.8-beta", t.TempDir(), testServiceOptions(srv)...)

	task := &Task{ID: "missentry1"}
	archivePath, err := s.downloadRelease(context.Background(), task, testRelease(srv, true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.verifyDownload(context.Background(), task, testRelease(srv, true), archivePath)
	if err == nil || !strings.Contains(err.Error(), "为空") {
		t.Fatalf("verify with empty sums = %v, want failure", err)
	}
	if dirExists(s.taskDir(task.ID)) {
		t.Fatal("task workspace must be wiped after a missing entry")
	}
}

// TestChecksumsFileMissing: a release without checksums.txt is refused
// before anything is fetched (verification is mandatory).
func TestChecksumsFileMissing(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{testArchiveNm: archive})
	s := NewService("v0.7.8-beta", t.TempDir(), testServiceOptions(srv)...)

	task := &Task{ID: "nosums0001"}
	if _, err := s.downloadRelease(context.Background(), task, testRelease(srv, false)); err == nil {
		t.Fatal("release without checksums.txt must be refused")
	}
	if dirExists(s.taskDir(task.ID)) {
		t.Fatal("no workspace may remain when the sums asset is missing")
	}
}

// TestExtractMissingPayload: an archive without both binaries fails and
// cleans up.
func TestExtractMissingPayload(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})
	s := NewService("v0.7.8-beta", t.TempDir(), testServiceOptions(srv)...)

	task := &Task{ID: "noclitask1"}
	archivePath, err := s.downloadRelease(context.Background(), task, testRelease(srv, true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.verifyDownload(context.Background(), task, testRelease(srv, true), archivePath)
	if err == nil || !strings.Contains(err.Error(), "缺少") {
		t.Fatalf("verify = %v, want missing-payload error", err)
	}
	if dirExists(s.taskDir(task.ID)) {
		t.Fatal("task workspace must be wiped after a missing payload")
	}
}

// TestExtractTarTraversal: crafted entry paths cannot escape the task
// workspace — only base-name matches are extracted.
func TestExtractTarTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := buildTarGz(t, map[string][]byte{
		"../evil.txt":  []byte("nope"),
		"kingmoat":     []byte(testPayloadA),
		"kingmoat-cli": []byte(testPayloadB),
	})
	if err := extractArchiveBytes(t, archive, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kingmoat", "kingmoat-cli"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("payload %s missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.txt")); err == nil {
		t.Fatal("traversal entry escaped the extraction directory")
	}
}

// extractArchiveBytes writes the archive to disk and extracts it.
func extractArchiveBytes(t *testing.T, archive []byte, dir string) error {
	t.Helper()
	p := filepath.Join(dir, "pkg.tar.gz")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return extractArchive(p, dir)
}

// TestDownloadSizeCapContentLength: a Content-Length above the cap is
// rejected before the body is transferred.
func TestDownloadSizeCapContentLength(t *testing.T) {
	body := bytes.Repeat([]byte("a"), 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithHTTPClient(srv.Client()), WithAllowedHosts([]string{"127.0.0.1"}), WithPlatform("linux", "amd64"))

	dest := filepath.Join(t.TempDir(), "out.bin")
	if _, err := s.downloadFile(context.Background(), srv.URL+"/big.bin", dest, 1024); err == nil {
		t.Fatal("download above the size cap must fail")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("failed download must not leave the destination file")
	}
}

// TestDownloadSizeCapStreamed: without a Content-Length the LimitReader
// backstop stops an oversized stream.
func TestDownloadSizeCapStreamed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 8; i++ { // 8 KiB total, chunked
			_, _ = w.Write(bytes.Repeat([]byte("b"), 1024))
			fl.Flush()
		}
	}))
	defer srv.Close()
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithHTTPClient(srv.Client()), WithAllowedHosts([]string{"127.0.0.1"}), WithPlatform("linux", "amd64"))

	dest := filepath.Join(t.TempDir(), "out.bin")
	if _, err := s.downloadFile(context.Background(), srv.URL+"/stream.bin", dest, 1024); err == nil {
		t.Fatal("streamed download above the size cap must fail")
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("failed streamed download must not leave the destination file")
	}
}

// TestDownloadSchemeAndAllowlist: non-HTTPS URLs and non-allowlisted hosts
// are refused before any request is made.
func TestDownloadSchemeAndAllowlist(t *testing.T) {
	s := NewService("v0.7.8-beta", t.TempDir(), WithPlatform("linux", "amd64"))
	dest := filepath.Join(t.TempDir(), "out.bin")

	if _, err := s.downloadFile(context.Background(), "http://gitee.com/x.bin", dest, 1024); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plain-http download = %v, want HTTPS refusal", err)
	}
	if _, err := s.downloadFile(context.Background(), "https://evil.example.com/x.bin", dest, 1024); err == nil || !strings.Contains(err.Error(), "来源域名") {
		t.Fatalf("foreign-host download = %v, want allowlist refusal", err)
	}
	// Allowlist matching is case-insensitive and tolerates a trailing dot
	// (pure checks — no request is issued).
	if !s.hostAllowed("GITEE.com") || !s.hostAllowed("gitee.com.") {
		t.Fatal("allowed origin must match case-insensitively with trailing dot")
	}
	if s.hostAllowed("evil.example.com") {
		t.Fatal("foreign host must not pass the allowlist")
	}
}

// TestDownloadHTTPStatusError: non-200 responses fail the download.
func TestDownloadHTTPStatusError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithHTTPClient(srv.Client()), WithAllowedHosts([]string{"127.0.0.1"}), WithPlatform("linux", "amd64"))
	dest := filepath.Join(t.TempDir(), "out.bin")
	if _, err := s.downloadFile(context.Background(), srv.URL+"/gone.bin", dest, 1024); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 download = %v, want status error", err)
	}
}

// TestParseChecksumsFormats pins the tolerated sums-file spellings.
func TestParseChecksumsFormats(t *testing.T) {
	h := sha256Hex([]byte("x"))
	good, err := parseChecksums(h + "  name.tar.gz\n" + strings.ToUpper(h) + " *second.zip\r\n" + h + " third.bin")
	if err != nil {
		t.Fatal(err)
	}
	if good["name.tar.gz"] != h || good["second.zip"] != h || good["third.bin"] != h {
		t.Fatalf("parsed = %v", good)
	}
	for _, bad := range []string{"nohash\n", "zz  name\n", ""} {
		if _, err := parseChecksums(bad); err == nil {
			t.Fatalf("parseChecksums(%q) = nil error, want failure", bad)
		}
	}
	if _, err := parseChecksums(""); err == nil {
		t.Fatal("empty sums must error")
	}
}

// TestSanitizeFileName pins the last-resort filename guard.
func TestSanitizeFileName(t *testing.T) {
	cases := map[string]string{
		"kingmoat.tar.gz":      "kingmoat.tar.gz",
		"dir/kingmoat.tar.gz":  "kingmoat.tar.gz",
		"dir\\kingmoat.tar.gz": "kingmoat.tar.gz",
		"../../evil":           "evil",
		"..":                   "",
	}
	for in, want := range cases {
		if got := sanitizeFileName(in); got != want {
			t.Fatalf("sanitizeFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTaskEndToEndDownload wires the real checker-shaped feed, the real
// download and verify defaults, and fake replace/restart hooks: the task
// must traverse into success with the payloads on disk.
func TestTaskEndToEndDownload(t *testing.T) {
	archive := buildTarGz(t, map[string][]byte{"kingmoat": []byte(testPayloadA), "kingmoat-cli": []byte(testPayloadB)})
	srv := assetServer(t, map[string][]byte{
		testArchiveNm: archive,
		checksumsName: []byte(sumsFile(map[string][]byte{testArchiveNm: archive})),
	})

	var mu sync.Mutex
	var artifactDir string
	s := NewService("v0.7.8-beta", t.TempDir(), append(testServiceOptions(srv),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*testRelease(srv, true)}, nil
		}),
		WithReplacer(func(ctx context.Context, t *Task) error { return nil }),
		WithRestarter(func(ctx context.Context, t *Task) error {
			mu.Lock()
			artifactDir = t.artifactDir
			mu.Unlock()
			return nil
		},
		))...)

	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	done := waitTask(t, s, task.ID, TaskSuccess)
	if done.TargetVersion != testVersion {
		t.Fatalf("target = %q, want %s", done.TargetVersion, testVersion)
	}
	mu.Lock()
	defer mu.Unlock()
	if artifactDir == "" {
		t.Fatal("replace stage never saw the artifact dir")
	}
	for _, name := range []string{"kingmoat", "kingmoat-cli"} {
		if _, err := os.Stat(filepath.Join(artifactDir, name)); err != nil {
			t.Fatalf("payload %s missing after end-to-end run: %v", name, err)
		}
	}
}

// TestPlatformUnsupportedTask: platforms without packages fail at the
// download stage with a clear reason.
func TestPlatformUnsupportedTask(t *testing.T) {
	rel := &Release{TagName: testVersion, Assets: []Asset{{Name: testArchiveNm}}}
	s := NewService("v0.7.8-beta", t.TempDir(),
		WithChecker(func(ctx context.Context) ([]Release, error) {
			return []Release{*rel}, nil
		}),
		WithPlatform("darwin", "arm64"))
	task, err := s.Start("")
	if err != nil {
		t.Fatal(err)
	}
	failed := waitTask(t, s, task.ID, TaskFailed)
	if !strings.Contains(failed.Error, "不提供在线升级包") {
		t.Fatalf("unsupported-platform error = %q", failed.Error)
	}
}
