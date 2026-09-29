package naming

import (
	"path/filepath"
	"strings"
)

// LegacyDataDir is the data directory of the pre-rename layout (v0.7.9 and
// earlier: /var/lib/kingmoat). The v0.7.10 rename moved it to DataDir;
// deploy/install.sh rewrites stored paths during migration, and the runtime
// compat layer (internal/config.ResolveLegacyDataPath) remaps any path that
// still carries the old prefix (migration skipped, manual migration, or a
// historical revision the rewrite missed).
const LegacyDataDir = "/var/lib/kingmoat"

// DataDir is the current data directory layout (v0.7.10 and later:
// /var/lib/kingmoatwaf). It mirrors OLD_DATA_DIR / DATA_DIR in
// deploy/install.sh; the Go side defines its own copy on purpose so the
// data plane does not depend on shell variables.
const DataDir = "/var/lib/kingmoatwaf"

// RemapLegacyDataPath remaps an absolute path under the legacy data
// directory to the same location under the current data directory. ok
// reports whether the path carries the legacy prefix (checked WITH the
// trailing separator so sibling directories like /var/lib/kingmoat-xxx are
// never touched). The caller decides what to do when the remapped target
// does not exist — usually keep the original path and let the normal error
// path surface the problem.
func RemapLegacyDataPath(p string) (string, bool) {
	if !strings.HasPrefix(p, LegacyDataDir+"/") {
		return "", false
	}
	return DataDir + p[len(LegacyDataDir):], true
}

// NormalizePath canonicalizes a configured file path for equality
// comparisons: surrounding space is trimmed, separators are unified to "/",
// and a legacy data-directory prefix is remapped to the current one, so the
// pre-migration and post-migration spellings of the same file compare equal.
// Used by reference lookups (certificate library sites lists); actual file
// access goes through internal/config.ResolveLegacyDataPath instead, which
// probes the remapped target first.
func NormalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	if remapped, ok := RemapLegacyDataPath(p); ok {
		return remapped
	}
	return p
}
