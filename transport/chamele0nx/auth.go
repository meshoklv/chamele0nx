package chamele0nx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// tokenWindow is the validity window for HMAC auth tokens.
// Token = HMAC-SHA256(user_secret, floor(time/window) || server_id).
// Changes every 5 minutes, so DPI cannot replay old tokens.
const tokenWindow = 5 * time.Minute

// authTokenLen is the length of a valid token: base64url of a 32-byte
// HMAC-SHA256 digest, unpadded. Anything else cannot be one of ours, and
// checking the length first costs nothing.
const authTokenLen = 43

// GenerateAuthToken creates an HMAC-SHA256 auth token for the current time window.
// The token proves the client knows the user secret without revealing it.
//
// Format: base64url(HMAC-SHA256(secret, timestamp_bucket || server_id))
// The timestamp bucket is floor(unix_seconds / 300), so the token changes every 5 min.
func GenerateAuthToken(userSecret []byte, serverID string) string {
	bucket := time.Now().Unix() / int64(tokenWindow.Seconds())
	return generateTokenForBucket(userSecret, serverID, bucket)
}

// ValidateAuthToken checks if a token is valid for the current or previous time window.
// Accepts current and previous bucket to handle clock skew at boundaries.
func ValidateAuthToken(userSecret []byte, serverID string, token string) bool {
	// Reject wrong-length tokens before computing any HMAC. The length of a
	// candidate is not a secret — it is visible in the request either way —
	// and skipping the digest here is what keeps a flood of junk candidates
	// from costing the server real work. Every token that survives this is
	// still compared in constant time.
	if len(token) != authTokenLen {
		return false
	}
	bucket := time.Now().Unix() / int64(tokenWindow.Seconds())
	// Check current and previous window.
	for _, b := range []int64{bucket, bucket - 1} {
		expected := generateTokenForBucket(userSecret, serverID, b)
		if hmac.Equal([]byte(expected), []byte(token)) {
			return true
		}
	}
	return false
}

func generateTokenForBucket(secret []byte, serverID string, bucket int64) string {
	mac := hmac.New(sha256.New, secret)
	// hash.Hash.Write is documented never to return an error, so the only
	// failure Fprintf could report here is impossible by construction.
	// The bytes fed to the MAC are unchanged: "<bucket>|<server_id>".
	_, _ = fmt.Fprintf(mac, "%d|%s", bucket, serverID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// FormatCookie formats an auth token as a cookie string matching the cover
// site's framework format. The cookie must look like something the cover
// site's framework would actually set — never a raw HMAC in hex, which
// would stand out immediately to anyone who can read the header.
//
// Supported formats:
//   - "generic": sid=<base64url token>
//   - "wordpress": wordpress_logged_in_<hash>=<token>
//   - "django": sessionid=<token>
func FormatCookie(token string, format string) string {
	switch format {
	case "wordpress":
		// Hash prefix looks like a real WordPress cookie hash (first 8 chars of HMAC).
		h := sha256.Sum256([]byte(token))
		prefix := fmt.Sprintf("%x", h[:4])
		return fmt.Sprintf("wordpress_logged_in_%s=%s", prefix, token)
	case "django":
		return fmt.Sprintf("sessionid=%s", token)
	default:
		return fmt.Sprintf("sid=%s", token)
	}
}

// ParseCookie extracts the auth token from a cookie string.
func ParseCookie(cookie string, format string) string {
	var prefix string
	switch format {
	case "wordpress":
		// Find the value after the last '='.
		for i := len(cookie) - 1; i >= 0; i-- {
			if cookie[i] == '=' {
				return cookie[i+1:]
			}
		}
		return ""
	case "django":
		prefix = "sessionid="
	default:
		prefix = "sid="
	}

	if len(cookie) > len(prefix) && cookie[:len(prefix)] == prefix {
		return cookie[len(prefix):]
	}
	return ""
}
