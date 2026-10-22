# Third-party notices

Chamele0nX is AGPL-3.0-or-later (see `LICENSE`). It depends on the Go
modules below (versions from `go.mod`). Licences were read from the module
sources, not from memory.

| Module | Licence | Note |
|---|---|---|
| github.com/refraction-networking/utls | BSD-3-Clause | browser-accurate TLS fingerprints |
| github.com/bogdanfinn/utls | BSD-3-Clause | fork of utls |
| github.com/bogdanfinn/fhttp | **no licence file** | fork of Go `net/http`; see below |
| github.com/andybalholm/brotli | MIT | indirect |
| github.com/klauspost/compress | BSD-3-Clause / Apache-2.0 / MIT (mixed) | indirect |
| golang.org/x/crypto, x/net, x/sys, x/text | BSD-3-Clause | |

## Known risk: github.com/bogdanfinn/fhttp has no licence

The module carries no `LICENSE` file (checked in the module cache for
v0.6.8). Code inherited from Go's `net/http` is BSD-licensed, but the fork's
own changes grant no rights, so under default copyright rules they may not be
redistributed or modified. It is used by the client for Chrome's HTTP/2
fingerprint (`transport/chamele0nx/chamele0nx.go`) and by tests. It is a
compile-time dependency, not vendored into this repository, so no third-party
source is redistributed here. Docker images that bundle the compiled client
do contain it. Planned replacement: see `docs/en/ROADMAP.md`. If you
distribute binaries or images, take your own legal advice, or ask the
upstream maintainer to add a licence.
