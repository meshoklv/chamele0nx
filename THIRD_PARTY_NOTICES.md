# Third-party notices

Chamele0nX is AGPL-3.0-or-later (see `LICENSE`). It depends on the Go
modules below (versions from `go.mod`). Licences were read from the module
sources, not from memory.

| Module | Licence | Note |
|---|---|---|
| github.com/refraction-networking/utls | BSD-3-Clause | browser-accurate TLS fingerprints |
| github.com/imroc/req/v3 | MIT | HTTP/2 client with Chrome-exact SETTINGS, flow and header order |
| github.com/quic-go/quic-go | MIT | indirect (HTTP/3 support inside req, not used by Chamele0nX) |
| github.com/quic-go/qpack | MIT | indirect |
| github.com/icholy/digest | MIT | indirect |
| github.com/google/go-querystring | BSD-3-Clause | indirect |
| github.com/andybalholm/brotli | MIT | indirect |
| github.com/klauspost/compress | BSD-3-Clause / Apache-2.0 / MIT (mixed) | indirect |
| golang.org/x/crypto, x/net, x/sys, x/text | BSD-3-Clause | |

Run `go list -m all` for the full module graph, including test-only modules.
