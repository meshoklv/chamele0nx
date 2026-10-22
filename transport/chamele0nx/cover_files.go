package chamele0nx

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// coverFileServer serves a cover site directory the way a real web server
// does, which http.FileServer on its own does not.
//
// http.FileServer answers an unknown path with Go's built-in
// "404 page not found" — plain text, no styling, a fixed body no real site
// produces. A cover site whose pages are HTML but whose 404 is bare Go text
// answers as two different applications, and that difference is exactly the
// kind of thing an active prober looks for. deploy/cover-site ships a
// 404.html for this reason, and until now nothing ever served it.
//
// If the directory contains 404.html, it is returned for any path the file
// server could not satisfy, with status 404. Otherwise the FileServer's own
// response is passed through unchanged.
type coverFileServer struct {
	root     http.Dir
	files    http.Handler
	notFound string // path to 404.html, empty when the site does not ship one
}

func newCoverFileServer(dir string) http.Handler {
	cfs := &coverFileServer{
		root:  http.Dir(dir),
		files: http.FileServer(http.Dir(dir)),
	}
	candidate := filepath.Join(dir, "404.html")
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		cfs.notFound = candidate
	}
	return cfs
}

func (c *coverFileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if c.notFound == "" {
		c.files.ServeHTTP(w, r)
		return
	}
	rec := &notFoundInterceptor{ResponseWriter: w}
	c.files.ServeHTTP(rec, r)
	if !rec.intercepted {
		return
	}
	body, err := os.ReadFile(c.notFound)
	if err != nil {
		// The page vanished between startup and now. Fall back to what the
		// file server would have said rather than serving nothing.
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	// FileServer sets these for the response it was about to send; they do
	// not describe the page actually being returned.
	h.Del("Last-Modified")
	h.Del("X-Content-Type-Options")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(body)
}

// notFoundInterceptor swallows a 404 status and its body so the caller can
// substitute a real page. Every other status passes straight through.
type notFoundInterceptor struct {
	http.ResponseWriter
	intercepted bool
	wroteHeader bool
}

func (n *notFoundInterceptor) WriteHeader(code int) {
	if n.wroteHeader {
		return
	}
	n.wroteHeader = true
	if code == http.StatusNotFound {
		n.intercepted = true
		return
	}
	n.ResponseWriter.WriteHeader(code)
}

func (n *notFoundInterceptor) Write(p []byte) (int, error) {
	if n.intercepted {
		// Discard the built-in body; the caller writes the real page.
		return len(p), nil
	}
	if !n.wroteHeader {
		n.wroteHeader = true
	}
	return n.ResponseWriter.Write(p)
}

// Flush keeps the wrapper transparent to the shaping layer, which relies on
// the handler chain forwarding flushes.
func (n *notFoundInterceptor) Flush() {
	if f, ok := n.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
