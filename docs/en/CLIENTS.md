# Clients

There are two ways to talk to a Chamele0nX server: the command line client
in this repository, and the Go bindings that a native app can embed.

## The command line client

`chamele0nx-client` connects to a server and opens a SOCKS5 proxy on
localhost. Everything you point at that proxy goes through the tunnel;
everything else does not. It handles both TCP and UDP.

```bash
./bin/chamele0nx-client \
  -server vpn.example.com:443 \
  -secret-file ~/.config/chamele0nx/secret \
  -cookie-format wordpress \
  -port 1080
```

| Flag | Default | What it does |
|---|---|---|
| `-server` | — | Server address as `host:port`. Required. |
| `-secret` | — | Hex user secret. Visible in `ps`; prefer `-secret-file`. |
| `-secret-file` | — | Read the hex secret from a file. Also honours `$CHAMELE0NX_SECRET_FILE`. |
| `-server-id` | `chamele0nx-1` | Must match the server's `-server-id`; it is mixed into the auth token. |
| `-api-path` | `/api/v1/events` | Must match the server. |
| `-cookie-format` | `generic` | `generic`, `wordpress` or `django`. Must match the server. |
| `-sni` | host from `-server` | TLS server name to present. |
| `-profile` | empty | Shaping profile for the upstream direction. Empty resolves to the built-in `DefaultSaaSProfile`. |
| `-port` | `0` (random) | Local SOCKS5 port. |
| `-check` | off | Connect, verify egress through the tunnel, print the result, exit. |
| `-check-timeout` | `30s` | How long `-check` waits, including one reconnect. |
| `-cover` | empty | Cover profile ID. Empty resolves to `saas-http2`, the only one compiled in. |
| `-log-format` | `text` | `text` or `json`. |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `-version` | — | Print build information and exit. |

The SOCKS5 listener stays on its port for the life of the process. If the
tunnel underneath drops, the client rebuilds it with exponential backoff and
applications keep their proxy settings. A network failure backs off from one
second to a minute; a rejected secret backs off from ten seconds to five
minutes, because retrying a credential the server has already refused is
both useless and conspicuous.

Verify a server without configuring anything:

```bash
./bin/chamele0nx-client -server vpn.example.com:443 -secret-file ./secret -check
```

It reports the external address the tunnel exits from. If that address is
your server, the whole path works.

### Using the proxy

```bash
curl -x socks5h://127.0.0.1:1080 https://example.org/
```

Use `socks5h`, not `socks5`: the `h` sends DNS through the tunnel. With
plain `socks5` your resolver still leaks every name you visit to the local
network.

Firefox takes a SOCKS5 proxy natively, with "Proxy DNS when using SOCKS
v5" switched on. Chrome needs `--proxy-server="socks5://127.0.0.1:1080"`
on the command line. System-wide routing needs a tun device and is out of
scope for this client.

## Mobile and desktop apps

`mobile/` builds with `gomobile bind` into an `.xcframework` for
Apple platforms. The binding is deliberately
small, because gomobile only passes simple types across the boundary.

| Call | Returns | Notes |
|---|---|---|
| `Version()` | string | Smoke test that the framework loaded. |
| `NewClient(endpointJSON)` | handle | Configuration arrives as a JSON string. |
| `Start()` / `StartOnPort(port)` | SOCKS5 address | Starts the reconnect loop. |
| `Stop()` | error | Stops accepting new connections and tears the tunnel down. |
| `SocksAddr()` | string | Where the proxy is listening. |
| `Status()` | JSON string | Running, stopped, connection counters, last error. |
| `RecentLogs()` | string | A ring buffer of recent log lines, for a debug screen. |

Build them like this:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

# gomobile generates code that imports golang.org/x/mobile/bind, so the
# module has to require it. It is not a dependency of the transport itself
# and is deliberately not in go.mod; add it in your checkout before binding.
go get golang.org/x/mobile/bind

gomobile bind -target=ios     -o Chamele0nX.xcframework ./mobile
```

**No mobile application ships from this repository.** The binding gives
an app a local SOCKS5 proxy; turning that into a system-wide VPN needs
platform work that lives in the app: a packet tunnel provider on Apple
platforms and something that converts IP
packets into SOCKS5 connections in between.

Three things are worth knowing before you build that layer:

- **Set the tunnel MTU to 1280.** At 1500, large packets and QUIC
  handshakes fail on paths that cannot carry them, and the failure looks
  like "some sites do not load" rather than like an MTU problem.
- **Route UDP as UDP.** A packet-tunnel library configured to carry UDP
  over TCP will silently drop DNS and QUIC, and the symptom is that
  applications which resolve names through the tunnel stop working while
  applications with hardcoded addresses keep going. The server has
  handled real UDP since the UDP stream types were added; use them.
- **Exclude the decoy driver's sockets from the tunnel.** The decoy
  driver fetches third-party domains in the background so the client's
  own traffic mix looks like a browser's. Those fetches only work if they
  leave the device outside the tunnel. Route them into it and you get the
  opposite of the intended effect: the decoys become tunnel traffic,
  adding volume without adding a single plausible destination. On Apple
  platforms it means excluding their routes. See `decoy.go` and
  [THREAT-MODEL.md](THREAT-MODEL.md).

## Writing your own client

The protocol is documented in [SPEC.md](SPEC.md). A minimal client needs
to do four things: complete a TLS handshake that does not stand out, send
an HTTP/2 POST with a valid auth cookie, exchange X25519 public keys, and
then speak the frame and stream layers. The Go implementation in
`transport/chamele0nx` is about 6000 lines excluding tests, and the
shaper is the part that matters — a client that skips shaping still
connects, and still looks like a VPN.
