package chamele0nx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoverFileServerServesCustom404 pins the behaviour deploy/cover-site
// advertises and http.FileServer does not provide: an unknown path returns
// the site's own 404 page, not Go's plain-text "404 page not found". A cover
// site whose pages are HTML but whose 404 is bare Go text answers as two
// different applications, which is what an active prober looks for.
func TestCoverFileServerServesCustom404(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<!doctype html><title>Home</title>")
	writeFile(t, filepath.Join(dir, "404.html"), "<!doctype html><title>Not found</title><p>gone</p>")

	h := newCoverFileServer(dir)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/no/such/page", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Not found") || !strings.Contains(body, "gone") {
		t.Errorf("body %q is not the site's 404 page", body)
	}
	if strings.Contains(body, "404 page not found") {
		t.Error("Go's built-in 404 body leaked through")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type %q, want text/html", ct)
	}
	if got, want := rec.Header().Get("Content-Length"), itoa(len(body)); got != want {
		t.Errorf("Content-Length is %q, want %q for the %d bytes written", got, want, len(body))
	}
}

// TestCoverFileServerPassesThroughSuccess makes sure the wrapper is invisible
// for everything that is not a 404.
func TestCoverFileServerPassesThroughSuccess(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<!doctype html><title>Home</title>")
	writeFile(t, filepath.Join(dir, "404.html"), "custom")
	writeFile(t, filepath.Join(dir, "app.css"), "body{}")

	h := newCoverFileServer(dir)

	// http.FileServer redirects /index.html to / by design; the wrapper must
	// pass that through untouched rather than turning it into a 404.
	for _, tc := range []struct {
		path string
		code int
	}{
		{"/", http.StatusOK},
		{"/app.css", http.StatusOK},
		{"/index.html", http.StatusMovedPermanently},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.code {
			t.Errorf("%s returned %d, want %d", tc.path, rec.Code, tc.code)
		}
		if strings.Contains(rec.Body.String(), "custom") {
			t.Errorf("%s was answered with the 404 page", tc.path)
		}
	}
}

// TestCoverFileServerWithout404 keeps the fallback honest: a site that ships
// no 404.html still gets the file server's own response.
func TestCoverFileServerWithout404(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "index.html"), "<!doctype html><title>Home</title>")

	rec := httptest.NewRecorder()
	newCoverFileServer(dir).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("no body at all — the response must still look like a web server's")
	}
}

// TestShippedCoverSiteHas404 ties the repository's own sample site to the
// behaviour above, so deleting the page does not silently regress the docs.
func TestShippedCoverSiteHas404(t *testing.T) {
	const path = "../../deploy/cover-site/404.html"
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("deploy/cover-site no longer ships a 404.html: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
