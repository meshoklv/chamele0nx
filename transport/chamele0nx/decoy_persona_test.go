package chamele0nx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUnauthorizedResponseMatchesCoverPersona pins the cover story's internal
// consistency.
//
// The session cookie already commits the server to a framework: FormatCookie
// emits a WordPress or Django cookie so the header does not stand out. The
// refusal has to belong to the same application. It used to be a flat 401
// carrying Django REST Framework's exact wording under a key DRF does not
// use, regardless of which framework the cookie claimed. That mismatch is
// free evidence for anyone probing the endpoint.
func TestUnauthorizedResponseMatchesCoverPersona(t *testing.T) {
	for _, tc := range []struct {
		format     string
		wantStatus int
		wantInBody string
	}{
		{
			// DRF with session authentication has no scheme to name, so it
			// answers 403 rather than 401.
			format:     "django",
			wantStatus: http.StatusForbidden,
			wantInBody: `"detail"`,
		},
		{
			format:     "wordpress",
			wantStatus: http.StatusUnauthorized,
			wantInBody: `"rest_not_logged_in"`,
		},
		{
			format:     "generic",
			wantStatus: http.StatusUnauthorized,
			wantInBody: `"unauthorized"`,
		},
		{
			// An unset format must behave like the generic persona.
			format:     "",
			wantStatus: http.StatusUnauthorized,
			wantInBody: `"unauthorized"`,
		}} {
		t.Run("format_"+tc.format, func(t *testing.T) {
			srv := &Server{config: ServerConfig{CookieFormat: tc.format}}

			call := func(method string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				srv.apiDecoy(rec, httptest.NewRequest(method, "/api/v1/events", nil))
				return rec
			}

			get, post := call(http.MethodGet), call(http.MethodPost)

			if get.Code != tc.wantStatus {
				t.Errorf("GET status %d, want %d", get.Code, tc.wantStatus)
			}
			// GET and POST must stay indistinguishable: an endpoint that
			// answers them differently is two applications at one path.
			if get.Code != post.Code || get.Body.String() != post.Body.String() {
				t.Errorf("GET and POST differ: %d %q vs %d %q",
					get.Code, get.Body.String(), post.Code, post.Body.String())
			}

			// No persona sends WWW-Authenticate. RFC 9110 15.5.2 says a 401
			// should carry one, and the software being imitated does not —
			// verified against live WordPress installs, which answer 401 with
			// no such header. Sending one the real thing omits is a tell, so
			// the imitation wins over the specification here.
			if auth := get.Header().Get("WWW-Authenticate"); auth != "" {
				t.Errorf("sent WWW-Authenticate %q; the imitated software sends none", auth)
			}

			if !strings.Contains(get.Body.String(), tc.wantInBody) {
				t.Errorf("body %q does not contain %q", get.Body.String(), tc.wantInBody)
			}
			if tc.format == "wordpress" {
				if ct := get.Header().Get("Content-Type"); ct != "application/json; charset=UTF-8" {
					t.Errorf("Content-Type %q does not match what WordPress states", ct)
				}
			}

			// No data ever reaches an anonymous caller.
			if strings.Contains(get.Body.String(), `"events"`) {
				t.Errorf("anonymous body leaked events: %s", get.Body.String())
			}
		})
	}
}

// TestDjangoPersonaDoesNotClaimWordPressWording guards the specific mismatch
// that prompted the change: DRF's sentence must not appear under a persona
// that is not Django.
func TestDjangoPersonaDoesNotClaimWordPressWording(t *testing.T) {
	const drfWording = "Authentication credentials were not provided."

	for _, format := range []string{"wordpress", "generic", ""} {
		srv := &Server{config: ServerConfig{CookieFormat: format}}
		rec := httptest.NewRecorder()
		srv.apiDecoy(rec, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
		if strings.Contains(rec.Body.String(), drfWording) {
			t.Errorf("format %q answers with Django REST Framework's wording: %s", format, rec.Body.String())
		}
	}
}
