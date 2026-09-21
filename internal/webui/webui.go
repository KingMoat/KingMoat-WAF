// Package webui serves the embedded management console: the Vue 3 + Element
// Plus SPA (built with Vite into ./dist and embedded into the binary) with an
// SPA fallback for client-side routes. All dynamic data is fetched client-side
// from /api/*.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the console SPA.
func Handler(version string) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err) // embedded at compile time; unreachable
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-KingMoat-Console", version)
		p := strings.TrimPrefix(r.URL.Path, "/")
		if _, statErr := fs.Stat(sub, p); statErr != nil {
			// SPA fallback: unknown paths serve the shell (hash router picks
			// the view client-side); API paths stay 404.
			if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/mcp") && r.URL.Path != "/openapi.json" {
				r.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}
