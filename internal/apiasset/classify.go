package apiasset

import "strings"

// Tag labels attached to learned assets. They drive both the UI filters and
// the risk engine signals (R4/R6/R7).
const (
	TagAuth   = "auth"
	TagAdmin  = "admin"
	TagExport = "export"
	TagFile   = "file"
)

// ClassifyTags derives tags from the normalized path.
func ClassifyTags(normPath string) []string {
	l := strings.ToLower(normPath)
	var tags []string
	switch {
	case containsAny(l, "/login", "/auth", "/token", "/sso", "/logout", "/signin", "/session"):
		tags = append(tags, TagAuth)
	case containsAny(l, "/admin", "/console", "/actuator", "/swagger", "/openapi", "/druid", "/jmx", "/debug", "/manage", "/dashboard", "/grafana", "/jenkins"):
		tags = append(tags, TagAdmin)
	case containsAny(l, "/export", "/download", "/report", "/backup", "/dump"):
		tags = append(tags, TagExport)
	case containsAny(l, "/upload", "/file", "/import", "/attach"):
		tags = append(tags, TagFile)
	}
	return tags
}

// IsLoginEndpoint reports whether (method, normPath) looks like an
// authentication attempt endpoint, used by the R3 brute-force detector.
func IsLoginEndpoint(method, normPath string) bool {
	if method != "POST" {
		return false
	}
	return containsAny(strings.ToLower(normPath), "/login", "/auth", "/token", "/sso", "/signin", "/session")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
