package master

import (
	"net/http"
	"os"
	"path/filepath"
)

func (s *Server) staticHandler(webDir string) http.Handler {
	fs := http.FileServer(http.Dir(webDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/subscription" {
			r = r.Clone(r.Context())
			r.URL.Path, r.URL.RawPath = "/", ""
		}
		if r.URL.Path == "/" {
			if _, err := os.Stat(filepath.Join(webDir, "index.html")); err != nil {
				http.Error(w, "web assets not built; run pnpm install --frozen-lockfile and pnpm build", http.StatusServiceUnavailable)
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}
