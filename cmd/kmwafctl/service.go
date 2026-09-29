package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/kingmoat/kingmoat/internal/config"
	"github.com/kingmoat/kingmoat/internal/naming"
	"github.com/kingmoat/kingmoat/internal/store"
)

const (
	serverBinaryName = naming.ServiceName
	unitName         = naming.ServiceName + ".service"

	newLayoutDataDir       = "/var/lib/kingmoatwaf"
	legacyLayoutDataDir    = "/var/lib/kingmoat"
	newLayoutInstallDir    = "/opt/kingmoatwaf"
	legacyLayoutInstallDir = "/opt/kingmoat"

	consoleEnvName = "console.env"
	configFileName = "config.json"
	consoleDBName  = "kingmoat.db"
)

var (
	installRecordPaths = []string{
		"/etc/kingmoatwaf-install.conf",
		"/etc/kingmoat-install.conf",
	}
	dataDirCandidates    = []string{newLayoutDataDir, legacyLayoutDataDir}
	installDirCandidates = []string{newLayoutInstallDir, legacyLayoutInstallDir}

	systemdHost   = func() bool { return runtime.GOOS == "linux" }
	runningAsRoot = func() bool { return os.Geteuid() == 0 }
	dirExists     = func(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }
	fileExists    = func(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

	systemctlRun = func(args ...string) (string, error) {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	probeBinaryVersion = func(binPath string) (string, error) {
		out, err := exec.Command(binPath, "-version").CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	primaryIPv4 = func() string {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return "127.0.0.1"
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
		return "127.0.0.1"
	}
)

type locations struct {
	InstallRecord string
	InstallDir    string
	DataDir       string
	DataDirSource string
}

// loadRuntimeConfig returns the live configuration published through the
// console (newest revision in the console DB). It falls back to nil when
// the store is unavailable or empty; callers then use the config.json
// install seed instead. The returned string describes the source that
// produced the config (or why the live path was not usable).
func loadRuntimeConfig(loc locations) (*config.Config, string) {
	dbPath := filepath.Join(loc.DataDir, consoleDBName)
	if !fileExists(dbPath) {
		return nil, "no console db at " + dbPath
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, "console db open failed: " + firstLine(err.Error())
	}
	defer st.Close()
	id, raw, err := st.CurrentRevision()
	if err != nil {
		return nil, "console db has no published config yet"
	}
	var c config.Config
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, fmt.Sprintf("console db revision %d unparseable", id)
	}
	return &c, fmt.Sprintf("console db %s revision %d (live)", dbPath, id)
}

func resolveLocations() locations {
	var loc locations
	for _, p := range installRecordPaths {
		if !fileExists(p) {
			continue
		}
		rec := parseInstallRecord(p)
		loc.InstallRecord = p
		loc.InstallDir = rec["INSTALL_DIR"]
		loc.DataDir = rec["DATA_DIR"]
		break
	}
	switch {
	case loc.DataDir != "":
		loc.DataDirSource = "install record"
	default:
		found := ""
		for _, c := range dataDirCandidates {
			if dirExists(c) {
				found = c
				break
			}
		}
		if found != "" {
			loc.DataDir = found
			loc.DataDirSource = "detected"
		} else {
			loc.DataDir = newLayoutDataDir
			loc.DataDirSource = "assumed (no install record found)"
		}
	}
	if loc.InstallDir == "" {
		for _, c := range installDirCandidates {
			if dirExists(c) {
				loc.InstallDir = c
				break
			}
		}
		if loc.InstallDir == "" {
			loc.InstallDir = newLayoutInstallDir
		}
	}
	return loc
}

func parseInstallRecord(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "INSTALL_DIR", "DATA_DIR":
			if strings.HasPrefix(v, "/") {
				out[k] = v
			}
		}
	}
	return out
}

func deriveDataDir() string {
	for _, p := range installRecordPaths {
		if !fileExists(p) {
			continue
		}
		if v := parseInstallRecord(p)["DATA_DIR"]; v != "" {
			return v
		}
	}
	for _, c := range dataDirCandidates {
		if dirExists(c) {
			return c
		}
	}
	return newLayoutDataDir
}

var consolePortLine = regexp.MustCompile(`^CONSOLE_PORT=(\d{1,5})$`)

func readConsolePort(envPath string) (string, string) {
	b, err := os.ReadFile(envPath)
	if err != nil {
		if os.IsPermission(err) {
			return "", "unreadable (permission denied; read as root or via sudo)"
		}
		return "", "unreadable (" + err.Error() + ")"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m := consolePortLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return m[1], "from " + envPath
		}
	}
	return "", "no CONSOLE_PORT line in " + envPath
}

func runServiceCommand(name string, _ []string) int {
	if !systemdHost() {
		fmt.Fprintf(os.Stderr, "kmwafctl %s: this subcommand requires a systemd (Linux) deployment; on Windows manage the service with NSSM as described in deploy/windows.md\n", name)
		return 1
	}
	switch name {
	case "status":
		return cmdStatus()
	case "start", "stop", "restart":
		return cmdServiceAction(name)
	case "config":
		return cmdConfig()
	}
	return 2
}

func cmdServiceAction(action string) int {
	if !runningAsRoot() {
		fmt.Fprintf(os.Stderr, "kmwafctl %s: this action requires root; re-run as: sudo kmwafctl %s\n", action, action)
		return 1
	}
	out, err := systemctlRun(action, unitName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "kmwafctl %s: systemctl %s %s failed: %v\n", action, action, unitName, err)
		if out != "" {
			fmt.Fprintln(os.Stderr, out)
		}
		return 1
	}
	state, _ := systemctlRun("is-active", unitName)
	if state == "" {
		state = "unknown"
	}
	fmt.Printf("%s: %s done, service is %s\n", unitName, action, state)
	return 0
}

type serviceStatus struct {
	Unit          string
	Active        string
	Enabled       string
	Version       string
	InstallDir    string
	DataDir       string
	DataDirSource string
	ConfigFile    string
	ConfigNote    string
	ConfigSource  string
	ListenHTTP    string
	ListenHTTPS   string
	Sites         int
	ConsolePort   string
	ConsoleNote   string
	ConsoleURL    string
}

func cmdStatus() int {
	st := collectStatus(resolveLocations())
	fmt.Print(renderStatus(st))
	return 0
}

func collectStatus(loc locations) serviceStatus {
	st := serviceStatus{
		Unit:          unitName,
		InstallDir:    loc.InstallDir,
		DataDir:       loc.DataDir,
		DataDirSource: loc.DataDirSource,
	}
	st.Active = systemctlVerdict("is-active")
	st.Enabled = systemctlVerdict("is-enabled")

	cfgPath := filepath.Join(loc.DataDir, configFileName)
	st.ConfigFile = cfgPath
	var cfg *config.Config
	live, liveNote := loadRuntimeConfig(loc)
	switch {
	case live != nil:
		cfg = live
		st.ConfigSource = liveNote
	default:
		st.ConfigNote = liveNote
		seed, err := config.Load(cfgPath)
		if err != nil {
			if fileExists(cfgPath) {
				st.ConfigNote += "; seed load failed: " + firstLine(err.Error())
			} else {
				st.ConfigNote += "; config.json missing"
			}
		} else {
			cfg = seed
			st.ConfigSource = cfgPath + " (install seed)"
		}
	}
	if cfg != nil {
		st.ListenHTTP = cfg.ListenHTTP
		st.ListenHTTPS = cfg.ListenHTTPS
		st.Sites = len(cfg.Sites)
	}

	port, note := readConsolePort(filepath.Join(loc.DataDir, consoleEnvName))
	st.ConsolePort, st.ConsoleNote = port, note
	if port != "" {
		st.ConsoleURL = fmt.Sprintf("https://%s:%s/", primaryIPv4(), port)
	} else {
		st.ConsoleURL = "-"
	}

	bin := filepath.Join(loc.InstallDir, serverBinaryName)
	if !fileExists(bin) {
		st.Version = "unknown (" + bin + " not found)"
	} else if v, err := probeBinaryVersion(bin); err != nil || v == "" {
		st.Version = "unknown (probe failed)"
	} else {
		st.Version = v
	}
	return st
}

func systemctlVerdict(sub string) string {
	out, err := systemctlRun(sub, unitName)
	switch {
	case err == nil && out != "":
		return out
	case out != "":
		return out
	default:
		if err != nil {
			return "unknown (" + firstLine(err.Error()) + ")"
		}
		return "unknown"
	}
}

func renderStatus(st serviceStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", st.Unit)
	writeKV(&b, "active", st.Active)
	writeKV(&b, "enabled", st.Enabled)
	writeKV(&b, "version", st.Version)
	writeKV(&b, "install dir", st.InstallDir)
	writeKV(&b, "data dir", st.DataDir+" ("+st.DataDirSource+")")
	if st.ConfigSource != "" {
		writeKV(&b, "config source", st.ConfigSource)
	} else {
		writeKV(&b, "config source", "unavailable")
	}
	if st.ConfigNote != "" {
		writeKV(&b, "note", st.ConfigNote)
	}
	writeKV(&b, "http listen", orDash(st.ListenHTTP))
	writeKV(&b, "https listen", orDash(st.ListenHTTPS))
	if st.ConfigSource != "" {
		writeKV(&b, "sites", fmt.Sprintf("%d", st.Sites))
	}
	if st.ConsolePort != "" {
		writeKV(&b, "console port", st.ConsolePort+" ("+st.ConsoleNote+")")
	} else {
		writeKV(&b, "console port", "- ("+st.ConsoleNote+")")
	}
	writeKV(&b, "console url", st.ConsoleURL)
	return b.String()
}

type configSummary struct {
	DataDir       string
	DataDirSource string
	ConfigFile    string
	ConfigSource  string
	LoadErr       string
	ListenHTTP    string
	ListenHTTPS   string
	ConsolePort   string
	ConsoleNote   string
	AcmeEmail     string
	Sites         []siteSummary
}

type siteSummary struct {
	Label     string
	Domains   []string
	Upstreams []string
	Mode      string
	WAF       bool
	Disabled  bool
	ACME      bool
}

func cmdConfig() int {
	sum := collectConfigSummary(resolveLocations())
	fmt.Print(renderConfigSummary(sum))
	return 0
}

func collectConfigSummary(loc locations) configSummary {
	cs := configSummary{
		DataDir:       loc.DataDir,
		DataDirSource: loc.DataDirSource,
		ConfigFile:    filepath.Join(loc.DataDir, configFileName),
	}
	cs.ConsolePort, cs.ConsoleNote = readConsolePort(filepath.Join(loc.DataDir, consoleEnvName))
	cfg, source := loadRuntimeConfig(loc)
	if cfg == nil {
		var err error
		cfg, err = config.Load(cs.ConfigFile)
		if err != nil {
			cs.LoadErr = source
			if fileExists(cs.ConfigFile) {
				cs.LoadErr += "; seed load failed: " + firstLine(err.Error())
			} else {
				cs.LoadErr += "; config.json missing"
			}
			return cs
		}
		source = cs.ConfigFile + " (install seed)"
	}
	cs.ConfigSource = source
	cs.ListenHTTP = cfg.ListenHTTP
	cs.ListenHTTPS = cfg.ListenHTTPS
	cs.AcmeEmail = cfg.AcmeEmail
	for i := range cfg.Sites {
		cs.Sites = append(cs.Sites, summarizeSite(&cfg.Sites[i]))
	}
	return cs
}

func summarizeSite(s *config.Site) siteSummary {
	sum := siteSummary{
		Domains:  s.Domains,
		Mode:     s.Mode,
		WAF:      s.WAF.IsEnabled(),
		Disabled: s.Disabled,
		ACME:     s.ACME != nil,
	}
	switch {
	case s.Name != "":
		sum.Label = s.Name
	case len(s.Domains) > 0:
		sum.Label = s.Domains[0]
	default:
		sum.Label = "(unnamed)"
	}
	for _, n := range s.Upstream.Nodes {
		sum.Upstreams = append(sum.Upstreams, n.Address)
	}
	return sum
}

func renderConfigSummary(cs configSummary) string {
	var b strings.Builder
	fmt.Fprintln(&b, "config summary (read-only)")
	writeKV(&b, "data dir", cs.DataDir+" ("+cs.DataDirSource+")")
	if cs.ConfigSource != "" {
		writeKV(&b, "config source", cs.ConfigSource)
	}
	if cs.LoadErr != "" {
		writeKV(&b, "note", cs.LoadErr)
	}
	if cs.ConfigSource != "" {
		writeKV(&b, "http listen", orDash(cs.ListenHTTP))
		writeKV(&b, "https listen", orDash(cs.ListenHTTPS))
	}
	if cs.ConsolePort != "" {
		writeKV(&b, "console port", cs.ConsolePort+" ("+cs.ConsoleNote+")")
	} else {
		writeKV(&b, "console port", "- ("+cs.ConsoleNote+")")
	}
	if cs.ConfigSource != "" {
		writeKV(&b, "acme email", orDash(cs.AcmeEmail))
		fmt.Fprintf(&b, "sites (%d)\n", len(cs.Sites))
		for _, s := range cs.Sites {
			fmt.Fprintln(&b, renderSiteLine(s))
		}
	} else {
		fmt.Fprintln(&b, "sites: unavailable - view them in the console, or inspect/fix the config file")
	}
	return b.String()
}

func renderSiteLine(s siteSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  - %s", s.Label)
	if len(s.Domains) > 1 {
		fmt.Fprintf(&b, " (+%d more)", len(s.Domains)-1)
	}
	state := "enabled"
	if s.Disabled {
		state = "DISABLED"
	}
	waf := "waf:on"
	if !s.WAF {
		waf = "waf:off"
	}
	fmt.Fprintf(&b, "  [%s %s", state, waf)
	if s.Mode != "" && s.Mode != "intercept" {
		fmt.Fprintf(&b, " mode:%s", s.Mode)
	}
	if s.ACME {
		fmt.Fprintf(&b, " acme")
	}
	fmt.Fprint(&b, "]")
	if len(s.Upstreams) > 0 {
		fmt.Fprintf(&b, "  -> %s", strings.Join(s.Upstreams, ", "))
	} else {
		fmt.Fprint(&b, "  -> (no upstream nodes)")
	}
	return b.String()
}

func writeKV(b *strings.Builder, key, val string) {
	fmt.Fprintf(b, "  %-14s: %s\n", key, val)
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
