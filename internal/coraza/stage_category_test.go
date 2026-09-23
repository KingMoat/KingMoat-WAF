package coraza

import (
	"strings"
	"testing"

	"github.com/kingmoat/kingmoat/internal/config"
)

func TestBuildCRSIncludesDefault(t *testing.T) {
	// Nil settings = all categories enabled.
	out := buildCRSIncludes(nil)
	for _, f := range config.WAFAlwaysOnFiles() {
		if !strings.Contains(out, f) {
			t.Fatalf("always-on file %s missing from output", f)
		}
	}
	for _, cat := range config.ValidWAFCategories() {
		f, _ := config.WAFCategoryFile(cat)
		if !strings.Contains(out, f) {
			t.Fatalf("category %s file %s missing from default output", cat, f)
		}
	}
}

func TestBuildCRSIncludesDisableSQLi(t *testing.T) {
	ws := &config.WAFSettings{Categories: []string{"xss", "rce", "lfi", "rfi", "php", "generic", "session", "java", "scanner"}}
	out := buildCRSIncludes(ws)

	// SQLi file must be absent.
	sqliFile, _ := config.WAFCategoryFile("sqli")
	if strings.Contains(out, sqliFile) {
		t.Fatalf("disabled category sqli file %s found in output", sqliFile)
	}

	// XSS file must be present.
	xssFile, _ := config.WAFCategoryFile("xss")
	if !strings.Contains(out, xssFile) {
		t.Fatalf("enabled category xss file %s missing from output", xssFile)
	}

	// Always-on files must be present.
	for _, f := range config.WAFAlwaysOnFiles() {
		if !strings.Contains(out, f) {
			t.Fatalf("always-on file %s missing", f)
		}
	}
}

func TestBuildCRSIncludesDisableAll(t *testing.T) {
	// Empty categories list = only always-on files.
	ws := &config.WAFSettings{Categories: []string{}}
	out := buildCRSIncludes(ws)

	for _, cat := range config.ValidWAFCategories() {
		f, _ := config.WAFCategoryFile(cat)
		if strings.Contains(out, f) {
			t.Fatalf("disabled category %s file %s found", cat, f)
		}
	}
	for _, f := range config.WAFAlwaysOnFiles() {
		if !strings.Contains(out, f) {
			t.Fatalf("always-on file %s missing", f)
		}
	}
}

func TestBuildCRSIncludesOrder(t *testing.T) {
	// Verify includes are emitted in CRS file-number order.
	out := buildCRSIncludes(nil)
	prev := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Include @owasp_crs/REQUEST-") {
			continue
		}
		var num int
		// Extract the 3-digit CRS number.
		rest := strings.TrimPrefix(line, "Include @owasp_crs/REQUEST-")
		if len(rest) < 3 {
			continue
		}
		for _, c := range rest[:3] {
			if c < '0' || c > '9' {
				continue
			}
		}
		num = int(rest[0]-'0')*100 + int(rest[1]-'0')*10 + int(rest[2]-'0')
		if num < prev {
			t.Fatalf("include order violated: %d after %d\n%s", num, prev, out)
		}
		prev = num
	}
}
