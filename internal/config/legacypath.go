package config

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/kingmoat/kingmoat/internal/naming"
)

// legacyPathWarned records the configured paths whose legacy-prefix remap
// has already been logged: one warning per path per process lifetime keeps
// the log readable without hiding the situation (a hot reload rebuilds
// every site, so an unlimited warning would repeat on each rebuild).
var legacyPathWarned sync.Map

// legacyDataFileExists probes the remapped target; a package-level
// indirection so tests can simulate both outcomes on any platform.
var legacyDataFileExists = func(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ResolveLegacyDataPath resolves a configured absolute path for actual file
// access. A path still carrying the pre-rename data-directory prefix
// (/var/lib/kingmoat/) is remapped to the current layout
// (/var/lib/kingmoatwaf/) when the remapped file exists — the signature of
// a stored path that outlived the v0.7.10 data-directory migration (the
// install.sh rewrite is best-effort and does not cover hand-migrated
// installs). The warning is capped at one per path per process lifetime.
//
// When the remapped target does not exist the original path is returned
// unchanged, so the caller's normal error path reports the configured path
// as-is; this also keeps a deployment that still runs on the legacy layout
// (files really under /var/lib/kingmoat) working: its remapped targets do
// not exist, so nothing is remapped.
func ResolveLegacyDataPath(p string, logger *slog.Logger) string {
	remapped, ok := naming.RemapLegacyDataPath(p)
	if !ok {
		return p
	}
	if !legacyDataFileExists(remapped) {
		return p
	}
	if logger != nil {
		if _, loaded := legacyPathWarned.LoadOrStore(p, struct{}{}); !loaded {
			logger.Warn("legacy data-dir path remapped to the current layout",
				"configured_path", p,
				"resolved_path", remapped,
				"legacy_data_dir", naming.LegacyDataDir,
				"data_dir", naming.DataDir)
		}
	}
	return remapped
}

// LegacyPathHint returns a remediation hint for a configured path that
// still carries the legacy data-directory prefix; "" for any other path.
// Callers append it to file-open failures so a post-migration "file not
// found" explains itself instead of looking like a lost certificate.
func LegacyPathHint(p string) string {
	if _, ok := naming.RemapLegacyDataPath(p); !ok {
		return ""
	}
	return fmt.Sprintf("（疑似升级迁移导致路径失效：旧数据目录 %s 已迁移至 %s，请更新配置或重新在控制台选择证书）",
		naming.LegacyDataDir, naming.DataDir)
}
