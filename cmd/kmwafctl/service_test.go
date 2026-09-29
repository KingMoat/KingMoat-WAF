package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	_ = w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func restoreSeams(t *testing.T) {
	t.Helper()
	oldSystemctl, oldRoot, oldSystemd := systemctlRun, runningAsRoot, systemdHost
	t.Cleanup(func() {
		systemctlRun, runningAsRoot, systemdHost = oldSystemctl, oldRoot, oldSystemd
	})
}

func TestServiceActionInvokesSystemctl(t *testing.T) {
	restoreSeams(t)
	runningAsRoot = func() bool { return true }
	systemdHost = func() bool { return true }
	var calls [][]string
	systemctlRun = func(args ...string) (string, error) {
		calls = append(calls, args)
		if len(args) > 0 && args[0] == "is-active" {
			return "active (running)", nil
		}
		return "", nil
	}
	for _, action := range []string{"start", "stop", "restart"} {
		calls = nil
		if code := runServiceCommand(action, nil); code != 0 {
			t.Fatalf("%s: exit = %d, want 0", action, code)
		}
		if len(calls) < 2 {
			t.Fatalf("%s: expected action call + is-active probe, got %v", action, calls)
		}
		want := []string{action, "kingmoatwaf.service"}
		if strings.Join(calls[0], " ") != strings.Join(want, " ") {
			t.Fatalf("%s: systemctl args = %v, want %v", action, calls[0], want)
		}
		if calls[1][0] != "is-active" {
			t.Fatalf("%s: post-action probe = %v, want is-active", action, calls[1])
		}
	}
}

func TestServiceActionFailsWithSystemctlDiagnostics(t *testing.T) {
	restoreSeams(t)
	runningAsRoot = func() bool { return true }
	systemdHost = func() bool { return true }
	systemctlRun = func(args ...string) (string, error) {
		return "Failed to restart kingmoatwaf.service: Unit not found.", io.EOF
	}
	var code int
	errText := captureStderr(t, func() { code = runServiceCommand("restart", nil) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errText, "Unit not found") {
		t.Fatalf("stderr = %q, want systemctl diagnostics folded in", errText)
	}
}

func TestServiceActionNonRootGetsSudoHint(t *testing.T) {
	restoreSeams(t)
	runningAsRoot = func() bool { return false }
	systemdHost = func() bool { return true }
	var invoked bool
	systemctlRun = func(args ...string) (string, error) {
		invoked = true
		return "", nil
	}
	var code int
	errText := captureStderr(t, func() { code = runServiceCommand("stop", nil) })
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if invoked {
		t.Fatal("systemctl must not be invoked for a non-root caller")
	}
	if !strings.Contains(errText, "sudo kmwafctl stop") {
		t.Fatalf("stderr = %q, want a sudo kmwafctl stop hint", errText)
	}
}

func TestServiceCommandsRequireSystemd(t *testing.T) {
	restoreSeams(t)
	systemdHost = func() bool { return false }
	var invoked bool
	systemctlRun = func(args ...string) (string, error) {
		invoked = true
		return "", nil
	}
	for _, name := range []string{"status", "start", "stop", "restart", "config"} {
		var code int
		errText := captureStderr(t, func() { code = runServiceCommand(name, nil) })
		if code != 1 {
			t.Fatalf("%s: exit = %d, want 1", name, code)
		}
		if !strings.Contains(errText, "systemd") || !strings.Contains(errText, "windows.md") {
			t.Fatalf("%s: stderr = %q, want the systemd-only hint pointing at windows.md", name, errText)
		}
	}
	if invoked {
		t.Fatal("systemctl must not be invoked off-systemd")
	}
}

func TestStatusRendersView(t *testing.T) {
	st := serviceStatus{
		Unit:          "kingmoatwaf.service",
		Active:        "active (running)",
		Enabled:       "enabled",
		Version:       "kingmoatwaf v0.7.9-beta",
		InstallDir:    "/opt/kingmoatwaf",
		DataDir:       "/var/lib/kingmoatwaf",
		DataDirSource: "install record",
		ConfigFile:    "/var/lib/kingmoatwaf/config.json",
		ListenHTTP:    "0.0.0.0:80",
		ListenHTTPS:   "0.0.0.0:443",
		Sites:         3,
		ConsolePort:   "8443",
		ConsoleNote:   "from /var/lib/kingmoatwaf/console.env",
		ConsoleURL:    "https://10.0.0.15:8443/",
	}
	out := renderStatus(st)
	for _, want := range []string{
		"kingmoatwaf.service",
		"active        : active (running)",
		"enabled       : enabled",
		"version       : kingmoatwaf v0.7.9-beta",
		"data dir      : /var/lib/kingmoatwaf (install record)",
		"http listen   : 0.0.0.0:80",
		"https listen  : 0.0.0.0:443",
		"sites         : 3",
		"console port  : 8443 (from /var/lib/kingmoatwaf/console.env)",
		"console url   : https://10.0.0.15:8443/",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderStatus output missing %q:\n%s", want, out)
		}
	}
}

func TestParseInstallRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	content := "# comment\n" +
		"INSTALL_DIR=\"/opt/kingmoatwaf\"\n" +
		"DATA_DIR=\"/var/lib/kingmoatwaf\"\n" +
		"UNRELATED=\"x\"\n" +
		"DATA_DIR=\"relative/path\"\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := parseInstallRecord(path)
	if rec["INSTALL_DIR"] != "/opt/kingmoatwaf" || rec["DATA_DIR"] != "/var/lib/kingmoatwaf" {
		t.Fatalf("parseInstallRecord = %v, want the two whitelisted absolute values", rec)
	}
	if len(rec) != 2 {
		t.Fatalf("parseInstallRecord has %d keys, want 2 (whitelist)", len(rec))
	}
}

func TestResolveLocationsPrefersNewRecord(t *testing.T) {
	oldRecords, oldData, oldInstall := installRecordPaths, dataDirCandidates, installDirCandidates
	t.Cleanup(func() { installRecordPaths, dataDirCandidates, installDirCandidates = oldRecords, oldData, oldInstall })

	dir := t.TempDir()
	legacy := filepath.Join(dir, "kingmoat-install.conf")
	if err := os.WriteFile(legacy, []byte("INSTALL_DIR=\"/opt/kingmoat\"\nDATA_DIR=\"/var/lib/kingmoat\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installRecordPaths = []string{legacy}
	dataDirCandidates = []string{"/nonexistent-a", "/nonexistent-b"}
	installDirCandidates = []string{"/nonexistent-a", "/nonexistent-b"}
	loc := resolveLocations()
	if loc.InstallRecord != legacy || loc.DataDir != "/var/lib/kingmoat" || loc.InstallDir != "/opt/kingmoat" {
		t.Fatalf("resolveLocations = %+v, want values from the legacy record", loc)
	}
	if loc.DataDirSource != "install record" {
		t.Fatalf("DataDirSource = %q, want \"install record\"", loc.DataDirSource)
	}
}

func TestResolveLocationsDetectionFallback(t *testing.T) {
	oldRecords, oldData, oldInstall := installRecordPaths, dataDirCandidates, installDirCandidates
	t.Cleanup(func() { installRecordPaths, dataDirCandidates, installDirCandidates = oldRecords, oldData, oldInstall })

	installRecordPaths = []string{filepath.Join(t.TempDir(), "missing.conf")}
	detected := t.TempDir()
	dataDirCandidates = []string{detected}
	installDirCandidates = []string{}
	loc := resolveLocations()
	if loc.DataDir != detected || loc.DataDirSource != "detected" {
		t.Fatalf("DataDir = %q (%q), want detected %q", loc.DataDir, loc.DataDirSource, detected)
	}
	if loc.InstallDir != newLayoutInstallDir {
		t.Fatalf("InstallDir = %q, want the new-layout default", loc.InstallDir)
	}
}

func TestReadConsolePort(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "console.env")
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port, note := readConsolePort(envPath)
	if port != "8443" || !strings.Contains(note, "console.env") {
		t.Fatalf("readConsolePort = %q, %q; want 8443 with a source note", port, note)
	}

	if err := os.WriteFile(envPath, []byte("OTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port, note = readConsolePort(envPath)
	if port != "" || !strings.Contains(note, "no CONSOLE_PORT") {
		t.Fatalf("readConsolePort = %q, %q; want empty port with a no-line note", port, note)
	}

	port, note = readConsolePort(filepath.Join(dir, "missing.env"))
	if port != "" || !strings.Contains(note, "unreadable") {
		t.Fatalf("readConsolePort = %q, %q; want unreadable note", port, note)
	}
}

func TestReadConsolePortPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows chmod does not remove read access: denial not reproducible")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission denial not reproducible")
	}
	dir := t.TempDir()
	envPath := filepath.Join(dir, "console.env")
	if err := os.WriteFile(envPath, []byte("CONSOLE_PORT=8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(envPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(envPath, 0o600) })
	port, note := readConsolePort(envPath)
	if port != "" || !strings.Contains(note, "permission denied") {
		t.Fatalf("readConsolePort = %q, %q; want a permission-denied hint, not a stack trace", port, note)
	}
}

func validTestConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	cfg := `{
  "listen_http": "0.0.0.0:80",
  "listen_https": "0.0.0.0:443",
  "acme_email": "ops@example.com",
  "sites": [
    {"domains": ["example.com"], "upstream": {"nodes": [{"address": "http://10.0.0.10:8080"}]}},
    {"name": "app", "domains": ["app.example.com", "alt.example.com"], "disabled": true, "upstream": {"nodes": [{"address": "10.0.0.11:8080"}]}, "waf": {"enabled": false}}
  ]
}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigSummaryRenders(t *testing.T) {
	dir := t.TempDir()
	validTestConfig(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "console.env"), []byte("CONSOLE_PORT=8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loc := locations{DataDir: dir, DataDirSource: "install record", InstallDir: "/opt/kingmoatwaf"}
	cs := collectConfigSummary(loc)
	if cs.LoadErr != "" {
		t.Fatalf("collectConfigSummary LoadErr = %q, want a valid load", cs.LoadErr)
	}
	out := renderConfigSummary(cs)
	for _, want := range []string{
		"config summary (read-only)",
		"data dir      : " + dir + " (install record)",
		"http listen   : 0.0.0.0:80",
		"https listen  : 0.0.0.0:443",
		"console port  : 8443 (from " + filepath.Join(dir, "console.env") + ")",
		"acme email    : ops@example.com",
		"sites (2)",
		"- example.com",
		"-> http://10.0.0.10:8080",
		"- app",
		"[DISABLED waf:off]",
		"-> 10.0.0.11:8080",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("renderConfigSummary output missing %q:\n%s", want, out)
		}
	}
}

func TestConfigSummaryLoadFailureDegraded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	loc := locations{DataDir: dir, DataDirSource: "install record", InstallDir: "/opt/kingmoatwaf"}
	cs := collectConfigSummary(loc)
	if cs.LoadErr == "" {
		t.Fatal("LoadErr is empty, want the parse failure recorded")
	}
	out := renderConfigSummary(cs)
	for _, want := range []string{"config summary (read-only)", "load failed", "console port", "sites: unavailable"} {
		if !strings.Contains(out, want) {
			t.Fatalf("degraded config output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "http listen") {
		t.Fatal("degraded config output must not claim listener values from an unreadable config")
	}
}

func TestStatusCollectFromFiles(t *testing.T) {
	oldSystemctl := systemctlRun
	t.Cleanup(func() { systemctlRun = oldSystemctl })
	systemctlRun = func(args ...string) (string, error) {
		if args[0] == "is-active" {
			return "active", nil
		}
		if args[0] == "is-enabled" {
			return "enabled", nil
		}
		return "", nil
	}
	dir := t.TempDir()
	validTestConfig(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "console.env"), []byte("CONSOLE_PORT=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := collectStatus(locations{DataDir: dir, DataDirSource: "install record", InstallDir: dir})
	if st.Active != "active" || st.Enabled != "enabled" {
		t.Fatalf("Active/Enabled = %q/%q, want active/enabled", st.Active, st.Enabled)
	}
	if st.Sites != 2 || st.ListenHTTP != "0.0.0.0:80" {
		t.Fatalf("Sites/ListenHTTP = %d/%q, want 2/0.0.0.0:80", st.Sites, st.ListenHTTP)
	}
	if st.ConsolePort != "9443" {
		t.Fatalf("ConsolePort = %q, want 9443", st.ConsolePort)
	}
	if !strings.Contains(st.Version, "not found") {
		t.Fatalf("Version = %q, want a not-found hint for the absent server binary", st.Version)
	}
}

func TestSystemctlVerdictHandlesFailuresWithOutput(t *testing.T) {
	oldSystemctl := systemctlRun
	t.Cleanup(func() { systemctlRun = oldSystemctl })
	systemctlRun = func(args ...string) (string, error) {
		return "inactive", io.EOF
	}
	if got := systemctlVerdict("is-active"); got != "inactive" {
		t.Fatalf("verdict = %q, want the stdout verdict despite the nonzero exit", got)
	}
	systemctlRun = func(args ...string) (string, error) {
		return "", io.EOF
	}
	if got := systemctlVerdict("is-enabled"); !strings.HasPrefix(got, "unknown") {
		t.Fatalf("verdict = %q, want unknown when systemctl yields nothing", got)
	}
}
