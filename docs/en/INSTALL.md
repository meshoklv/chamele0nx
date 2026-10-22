# Installing a Chamele0nX server

This is the whole path, from an empty Ubuntu box to a working tunnel.
Follow it in order. Every command below is meant to be run on a fresh
server unless it says otherwise.

Throughout, `vpn.example.com` stands for your own domain. Replace it.

---

## 1. What you need

| | |
|---|---|
| **A VPS** | 1 vCPU and 1 GB RAM is enough for a handful of users. Ubuntu 22.04 or 24.04 assumed below. |
| **A domain name** | Pointing an `A` record at the server's IP. Not a subdomain of the hoster's shared domain. |
| **Ports 80 and 443 reachable** | 80 for the ACME challenge, 443 for everything else. |
| **Go 1.26** | To build. It does not have to be installed on the server; see cross-compiling below. |
| **Root or sudo** | For the service unit, the firewall and the sysctl file. |

**Why a domain is not optional.** Chamele0nX's whole defence is that the
server is indistinguishable from an ordinary HTTPS site. An ordinary
HTTPS site has a hostname, a certificate issued to that hostname, and a
browser that reaches it without warnings. A server answering on a bare
IP address with a self-signed certificate is a strong signal on its own:
almost nothing legitimate looks like that, and censorship systems are
happy to act on signals that cheap. There is no configuration that makes
up for it.

Pick a domain whose name matches the site you are going to put on it. If
the cover site is a support console, do not host it at
`fast-vpn-server-3.example`.

---

## 2. Build

```bash
git clone https://github.com/meshoklv/chamele0nx
cd chamele0nx
make build
```

`make build` writes four binaries into `./bin`:

| Binary | What it is |
|---|---|
| `chamele0nx-server` | The server. Serves the cover site and tunnels for authenticated clients. |
| `chamele0nx-client` | CLI client. Opens a local SOCKS5 proxy. |
| `chamele0nx-profiler` | Captures a traffic profile from a real website. |
| `chamele0nx-validator` | Statistical tests: does shaped output match a profile. |

Version metadata is stamped in at build time. Check it with:

```bash
./bin/chamele0nx-server -version
```

Other targets: `make test`, `make test-race`, `make vet`, `make lint`,
`make check` (what CI runs), `make clean`, `make help`.

### Cross-compiling for the server

If you build on a laptop and deploy to a Linux VPS, build a static
binary and copy it over:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" \
  -o bin/chamele0nx-server-linux-amd64 ./cmd/chamele0nx-server

scp bin/chamele0nx-server-linux-amd64 root@vpn.example.com:/usr/local/bin/chamele0nx-server
ssh root@vpn.example.com 'chmod 755 /usr/local/bin/chamele0nx-server'
```

Use `GOARCH=arm64` for ARM servers. `CGO_ENABLED=0` matters: it produces
a binary with no libc dependency, so it runs on a server whose
distribution is older than your build machine's.

---

## 3. Get a certificate

Install certbot and issue a certificate. The server binds `:443`, not
`:80`, so port 80 stays free for the HTTP-01 challenge.

```bash
sudo apt update
sudo apt install -y certbot
sudo certbot certonly --standalone -d vpn.example.com
```

The certificate lands in `/etc/letsencrypt/live/vpn.example.com/`.
`certbot.timer` renews it automatically, roughly twice a day, and does
nothing until the certificate is within 30 days of expiry.

### Key reuse on renewal

By default certbot generates a **new key pair** on every renewal. If any
of your clients pins the certificate's public key, every renewal breaks
every pinned client at once, with a handshake failure that looks exactly
like an attack.

If you pin, force key reuse:

```bash
sudo certbot renew --reuse-key --cert-name vpn.example.com
```

or add it permanently to `/etc/letsencrypt/renewal/vpn.example.com.conf`:

```ini
reuse_key = True
```

The CLI client in this repository does not pin. Out-of-tree mobile
clients built on `mobile/` may. Decide before you hand out clients,
because changing your mind later means shipping a new client build.

### Restarting the server after renewal

The server reads the certificate once at start. Create the service user
and a directory it can read from, then add a deploy hook so a renewal
actually takes effect:

```bash
sudo useradd -r -s /usr/sbin/nologin chamele0nx
sudo mkdir -p /etc/chamele0nx/tls
sudo chown root:chamele0nx /etc/chamele0nx/tls
sudo chmod 0750 /etc/chamele0nx/tls

sudo tee /etc/letsencrypt/renewal-hooks/deploy/chamele0nx-reload.sh >/dev/null <<'EOF'
#!/bin/sh
set -e
install -o chamele0nx -g chamele0nx -m 0640 \
  "$RENEWED_LINEAGE/fullchain.pem" /etc/chamele0nx/tls/fullchain.pem
install -o chamele0nx -g chamele0nx -m 0600 \
  "$RENEWED_LINEAGE/privkey.pem"   /etc/chamele0nx/tls/privkey.pem
systemctl restart chamele0nx-server
EOF
sudo chmod 755 /etc/letsencrypt/renewal-hooks/deploy/chamele0nx-reload.sh
```

The copy step exists because `/etc/letsencrypt/live` and `archive` are
readable only by root, and the server does not run as root. Copying the
current certificate into a directory the service user can read is
simpler and safer than loosening permissions on the certbot tree.

Put the current certificate there now, so the first start has one; the
hook keeps it fresh from then on.

```bash
sudo install -o chamele0nx -g chamele0nx -m 0640 \
  /etc/letsencrypt/live/vpn.example.com/fullchain.pem /etc/chamele0nx/tls/fullchain.pem
sudo install -o chamele0nx -g chamele0nx -m 0600 \
  /etc/letsencrypt/live/vpn.example.com/privkey.pem   /etc/chamele0nx/tls/privkey.pem
```

---

## 4. Put a real site behind it

Whatever is in `-cover-dir` is what an unauthenticated visitor sees. A
prober checking whether this host is a proxy sees the same thing.

```bash
sudo mkdir -p /var/www/cover
sudo cp -r deploy/cover-site/* /var/www/cover/
sudo chown -R chamele0nx:chamele0nx /var/www/cover
```

**Then replace it.** `deploy/cover-site/` is a deliberately bland
placeholder so the server does something sane out of the box. If every
deployment of this project ships the identical placeholder, that
placeholder becomes the fingerprint, and scanning for it finds every
server at once. That is precisely the failure the protocol exists to
avoid.

A cover site that holds up:

- looks like a product someone would plausibly host on **that** domain;
- has a login form that fails the way real login forms fail, not one
  that returns the same response for every input;
- serves several static assets, so one page load produces a burst of
  requests rather than a single one;
- returns a normal 404 for unknown paths;
- contains no reference to VPNs, proxies, censorship, or this project.

The strongest and least effort option is to point `-cover-dir` at a copy
of a real static site you actually run.

---

## 5. Create the secret

The secret is the only credential. Anyone holding it can use the tunnel;
nobody without it can tell the tunnel exists.

Generate 32 random bytes, hex-encoded:

```bash
openssl rand -hex 32
```

The server accepts any hex secret of 16 bytes or more, and refuses
anything shorter. Started with no secret at all, it generates one, prints
it to stderr, and uses it, which is fine for a first smoke test and
useless afterwards because a restart generates a different one.

### Never pass it as a command line argument

`-secret <hex>` works and you should not use it. Command line arguments
are visible to every user on the machine through `ps`, they end up in
your shell history, and they are captured by process accounting. The
server accepts the secret from four sources, in this order:

| Priority | Source | Notes |
|---|---|---|
| 1 | `-secret-file PATH` | Reads and trims the file. Preferred. |
| 2 | `-secret HEX` | Visible in `ps`. Avoid. |
| 3 | `$CHAMELE0NX_SECRET_FILE` | Path. What the systemd unit uses. |
| 4 | `$CHAMELE0NX_SECRET` | Value. Better than the flag, worse than a file. |

Command line arguments win over the environment, so a variable inherited
from a shell or a supervisor can never quietly override the flag an
operator typed. The client resolves its secret through the same four
sources, in the same order.

### Storing it with systemd credentials

The shipped unit uses `LoadCredentialEncrypted`. systemd encrypts the
secret against this host's key, decrypts it at start time into a tmpfs
directory only the service can read, and passes the path in `%d`. A copy
of the encrypted file taken to another machine is useless.

```bash
sudo mkdir -p /etc/chamele0nx
openssl rand -hex 32 | sudo systemd-creds encrypt \
  --name=chamele0nx-secret - /etc/chamele0nx/secret.cred
sudo chmod 600 /etc/chamele0nx/secret.cred
```

Keep a copy of the plaintext hex somewhere offline. You cannot recover it
from `secret.cred` on a different machine, and losing it means every
client has to be reconfigured.

If your system has no `systemd-creds`, fall back to a plain file:

```bash
openssl rand -hex 32 | sudo tee /etc/chamele0nx/secret >/dev/null
sudo chown chamele0nx:chamele0nx /etc/chamele0nx/secret
sudo chmod 600 /etc/chamele0nx/secret
```

and change the unit's last argument to `-secret-file /etc/chamele0nx/secret`.

---

## 6. Run it as a service

Install the shipped unit:

```bash
sudo mkdir -p /var/log/chamele0nx
sudo chown chamele0nx:chamele0nx /var/log/chamele0nx
sudo cp deploy/systemd/chamele0nx-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now chamele0nx-server
```

Edit the `ExecStart` paths in the unit if yours differ. As shipped it
expects `/usr/local/bin/chamele0nx-server`, certificates in
`/etc/chamele0nx/tls/`, the cover site in `/var/www/cover`, and a profile
at `/etc/chamele0nx/profile.json`. Drop the `-profile` line if you have
no profile file yet; the server falls back to a built-in downstream
profile.

Watch it start:

```bash
systemctl status chamele0nx-server
journalctl -u chamele0nx-server -n 50 --no-pager
journalctl -u chamele0nx-server -f          # live
```

### What the sandbox directives do

The unit is deliberately locked down. Briefly:

| Directive | Effect |
|---|---|
| `User=chamele0nx` | Not root. A compromise of the process is not a compromise of the box. |
| `AmbientCapabilities=CAP_NET_BIND_SERVICE` | Lets a non-root process bind `:443`. No `setcap` on the binary needed. |
| `CapabilityBoundingSet=` | That is the only capability it can ever hold. |
| `LoadCredentialEncrypted=` | Secret decrypted into tmpfs at start, host-bound, never on disk in the clear. |
| `NoNewPrivileges=yes` | No setuid escalation from inside the process. |
| `ProtectSystem=strict` | The whole filesystem is read-only except `ReadWritePaths`. |
| `ProtectHome=yes` | `/home`, `/root` and `/run/user` are invisible. |
| `PrivateTmp` / `PrivateDevices` | Its own `/tmp`; no raw device access. |
| `ProtectKernelTunables/Modules/Logs` | Cannot change sysctls, load modules, or read `dmesg`. |
| `ProtectProc=invisible` | Cannot see other users' processes in `/proc`. |
| `RestrictAddressFamilies=` | Only IPv4, IPv6 and Unix sockets. No raw or packet sockets. |
| `MemoryDenyWriteExecute=yes` | No writable-executable memory. Blocks a large class of injected payloads. |
| `SystemCallFilter=@system-service` plus the `~` denylist | No privileged, debug, mount or namespace syscalls. |
| `LockPersonality` / `RestrictRealtime` / `RestrictSUIDSGID` / `RestrictNamespaces` | Closes the usual sandbox escapes. |
| `LimitCORE=0` | No core dumps. A dump would contain session keys and the secret. |
| `UMask=0077` | Anything it writes is private to its own user. |
| `Restart=always`, `RestartSec=2` | Crash means restart, not outage. |
| `TimeoutStopSec=40` | Bounded shutdown, with room for the server's own 30 s drain on SIGTERM to finish first. |

Score the result if you want a second opinion:

```bash
systemd-analyze security chamele0nx-server
```

### Server flags, in full

Every flag below is what the binary accepts. Defaults in brackets.

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `:443` | Listen address. |
| `-cert` | — | TLS certificate chain, PEM. Required. |
| `-key` | — | TLS private key, PEM. Required. |
| `-api-path` | `/api/v1/events` | Path the tunnel rides on. Must match the client. |
| `-server-id` | `chamele0nx-1` | Server identifier. Mixed into the auth token, so it must match the client. |
| `-secret` | — | Hex secret. Visible in `ps`; prefer `-secret-file`. |
| `-secret-file` | — | Read the hex secret from this file. |
| `-cookie-format` | `generic` | `generic`, `wordpress` or `django`. Must match the client. |
| `-cover-dir` | — | Directory served to unauthenticated visitors. |
| `-profile` | — | Traffic profile JSON. Falls back to a built-in profile. |
| `-idle-timeout` | `5m` | Close relayed streams with no activity for this long. |
| `-log-format` | `json` | `text` or `json`. |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error`. |
| `-disable-downstream-shaping` | `false` | Kill switch. Turns off server-side record shaping. Weakens the defence; operator escape hatch only. Also settable with `CHAMELE0NX_DISABLE_DOWNSTREAM_SHAPING=1`. |
| `-version` | — | Print version, commit and build date, then exit. |

---

### Change the defaults that identify you

Four of those defaults are the same on every machine that runs this
software unchanged: the tunnel rides on `/api/v1/events`, the server
answers to `chamele0nx-1`, the cookie is in `generic` shape, and the
cover directory is a copy of `deploy/cover-site`. None of them is a
secret and none of them weakens the cryptography. They are worse than
that: they are a shared fingerprint. A scanner that learns one deployment
learns the shape of every other, and the cost of finding the rest drops
to the cost of a single request each.

So pick your own, and pick them to fit the cover story rather than to
look random:

| Flag | Choose |
|---|---|
| `-api-path` | A path the cover site would plausibly own. A dashboard has `/api/…`; a blog does not, and `/wp-json/wp/v2/…` fits it far better. |
| `-server-id` | Anything, as long as it is not the default. It is mixed into the auth token, never sent in clear. |
| `-cookie-format` | The framework your cover site claims to be. A WordPress-looking site setting a `sid` cookie contradicts itself. |
| `-cover-dir` | A site of your own. See section 4. |
| `-profile` | A profile captured from the site you are imitating. See [PROFILES.md](PROFILES.md). |

`-api-path`, `-server-id` and `-cookie-format` are part of the auth path,
so the client has to be given the same three values. Changing them is not
a rotation: existing clients stop connecting until they are updated, and
they fail by getting the cover site, exactly as a stranger would.

---

## 7. Firewall

Default deny, three ports open, nothing else.

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # ACME renewal
sudo ufw allow 443/tcp    # cover site and tunnel
sudo ufw enable
sudo ufw status verbose
```

Confirm nothing else is listening:

```bash
sudo ss -ltnp
sudo ss -ltn | grep -v '127.0.0.1'
```

Every line in that last command should be one you can explain. Any extra
open port is a second thing to fingerprint, and it can contradict the
story the cover site is telling. A host that claims to be a small SaaS
console has no business exposing a database, a metrics endpoint, or a
second web server on a high port.

---

## 8. TCP tuning

This is the single change with the largest effect on speed, and it has
nothing to do with the protocol.

```bash
sudo cp deploy/sysctl/99-chamele0nx-tcp.conf /etc/sysctl.d/
echo tcp_bbr | sudo tee /etc/modules-load.d/bbr.conf
sudo modprobe tcp_bbr
sudo sysctl --system
```

Verify it took:

```bash
sysctl net.ipv4.tcp_congestion_control     # want: bbr
sysctl net.core.default_qdisc              # want: fq
lsmod | grep bbr
```

**What it bought, measured.** On a long-haul path from a censored network
to a foreign VPS, raw HTTPS throughput from the server went from about
3.5 Mbit/s to about 22 Mbit/s after switching from CUBIC to BBR with
larger socket buffers. Nothing in the protocol changed. The default
congestion control collapses on a lossy international route, and no
amount of protocol tuning recovers what it loses. Tunnel throughput on
the same path settled around 20 Mbit/s afterwards.

The file also sets `tcp_mtu_probing=1`, which stops the connection from
blackholing on paths with broken path-MTU discovery, and
`tcp_notsent_lowat`, which keeps the kernel send queue short so that
shaping decisions are not buried under a multi-megabyte backlog.

---

## 9. Connect a client

Build the client on the machine that will use it:

```bash
make build
```

Put the secret in a file rather than on the command line:

```bash
umask 077
echo '<hex secret>' > ~/.chamele0nx-secret
```

Run it. The client opens a SOCKS5 listener on localhost and keeps it
bound for its whole lifetime, re-establishing the tunnel underneath on
failure with an exponential backoff from 1 s to 60 s.

```bash
./bin/chamele0nx-client \
  -server vpn.example.com:443 \
  -secret-file ~/.chamele0nx-secret \
  -server-id chamele0nx-1 \
  -cookie-format wordpress \
  -port 1080
```

`-server-id`, `-cookie-format` and `-api-path` must match the server. The
auth token is an HMAC over the time bucket and the server id, so a
mismatched id fails authentication and you get the cover site instead of
a tunnel.

Test the tunnel end to end without configuring anything else:

```bash
./bin/chamele0nx-client \
  -server vpn.example.com:443 \
  -secret-file ~/.chamele0nx-secret \
  -cookie-format wordpress \
  -check
```

`-check` brings the tunnel up, fetches your external IP through it,
prints it and exits. It should print the server's address, not yours. It
gives up after `-check-timeout` (30 s by default).

Then use the proxy:

```bash
curl -x socks5h://127.0.0.1:1080 https://example.org/
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

Use `socks5h://` (or `--socks5-hostname`), not `socks5://`. The `h` sends
DNS resolution through the tunnel. Without it your resolver sees every
hostname you visit, which is usually the exact thing you were trying to
avoid.

### Client flags used on this step

The full table is in [CLIENTS.md](CLIENTS.md). Connecting needs only
these, and the three that must match the server are listed above.

| Flag | Default | Meaning |
|---|---|---|
| `-server` | — | `host:port` of the server. Required. |
| `-secret-file` | — | Read the hex secret from this file. Use it instead of `-secret`. |
| `-port` | `0` | Local SOCKS5 port. 0 picks a random free one. |

---

## 10. Verify it looks like a website

Do these checks from a network that is not the server, with no client
running. This is what a prober sees.

**A browser** opening `https://vpn.example.com/` should get your cover
site, with a valid padlock and no certificate warning. Not a blank page,
not a default nginx page, not an error.

**An unauthenticated GET** returns the cover site:

```bash
curl -sS -o /dev/null -w 'HTTP=%{http_code}\n' https://vpn.example.com/
# expect: HTTP=200
```

**An unauthenticated request to the tunnel path** answers the way a real
cookie-protected endpoint answers: it refuses, and it refuses identically on
both methods it implements.

```bash
curl -sS -o /dev/null -w 'HTTP=%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' -d '{"x":1}' \
  https://vpn.example.com/api/v1/events
# expect: HTTP=401

curl -sS -o /dev/null -w 'HTTP=%{http_code}\n' \
  https://vpn.example.com/api/v1/events
# expect: HTTP=401 — the same answer as the POST above

curl -sS -i -X DELETE https://vpn.example.com/api/v1/events | head -n 5
# expect: HTTP/2 405 and an "allow: GET, POST" header
```

The refusal follows the framework named by `-cookie-format`, because the
session cookie already commits the cover site to one: `generic` and
`wordpress` answer 401, while `django` answers **403** — Django REST
Framework's session authentication has no scheme to name and downgrades the
status. Expect 403 there, not 401. None of them sends a `WWW-Authenticate`
header, because the software being imitated does not.

The error bodies are byte-identical between calls, and that is correct: a real
API's error bodies are constant too. Only the `X-Request-Id` header varies,
the way a request-tracing middleware emits it. An endpoint that handed data to
an anonymous caller — or that answered GET and POST as two different
applications — would be the tell.

**An unknown path** returns an ordinary 404:

```bash
curl -sS -i https://vpn.example.com/nope
# expect: HTTP/2 404
```

Look at the body, not just the code. If the cover directory contains a
`404.html`, that page is what unknown paths get, with status 404 and the
`Content-Type` of a page rather than of a file listing. `deploy/cover-site`
ships one, so a site copied from there is already consistent.

Leave that file out and the fallback is Go's static file server, whose 404
body is the plain string `404 page not found` — not what a WordPress or
Django site would return, and trivially recognisable. A cover site whose
pages are HTML and whose 404 is bare Go text answers as two different
applications, which is the kind of seam an active prober looks for. So:
ship a `404.html` that belongs to the same site as `index.html`, and do
not pick a framework whose 404 page is famous enough that its absence is
loud.

**The certificate** is issued to your domain, by a public CA, and is
valid:

```bash
echo | openssl s_client -connect vpn.example.com:443 \
  -servername vpn.example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

If clients pin the public key, record its fingerprint now and check it
again after every renewal:

```bash
openssl x509 -in /etc/chamele0nx/tls/fullchain.pem -pubkey -noout \
  | openssl pkey -pubin -outform der | sha256sum
```

**No extra ports** are open, from the outside:

```bash
nmap -Pn -p- vpn.example.com     # from another machine
```

22, 80 and 443. Nothing else.

---

## 11. Troubleshooting

| Symptom | Likely cause | What to check |
|---|---|---|
| Server exits at start, "usage" printed | `-cert` or `-key` missing | Both are required. Check the `ExecStart` paths exist. |
| `read secret file ...: permission denied` | Service user cannot read the secret | `ls -l` the file. It must be readable by `chamele0nx`. With systemd credentials, use `%d/chamele0nx-secret`, not a path of your own. |
| `secret too short` | Secret under 16 bytes | Regenerate with `openssl rand -hex 32`. |
| Server starts, `:443` not listening | Missing `CAP_NET_BIND_SERVICE`, or something else holds the port | `systemctl status`, then `sudo ss -ltnp \| grep :443`. |
| Cert error on start | Non-root process cannot read `/etc/letsencrypt` | Copy the pair into `/etc/chamele0nx/tls` with the deploy hook from section 3. |
| Browser gets a cert warning | Certificate for the wrong name, or expired, or only `cert.pem` given | Use `fullchain.pem`, not `cert.pem`. Check dates with `openssl x509 -noout -dates`. |
| `curl` to `/` returns 404 or an empty body | `-cover-dir` empty, wrong, or unreadable by the service user | `ls -l /var/www/cover`. It needs an `index.html`. |
| Client: connects, then "unauthorized", cover site instead of a tunnel | `-server-id`, `-cookie-format` or `-api-path` differ from the server | All three are part of the auth path. Compare them side by side. |
| Client: authentication fails intermittently | Clock skew beyond the token window | The token rotates every 5 minutes and the previous window is accepted, so skew above ~5 minutes breaks it. Run NTP on both ends. |
| Client: timeout, no response at all | Port 443 filtered on the path, or the address is blocked | Try from a different network. Section "If an address gets blocked" in [OPERATIONS.md](OPERATIONS.md). |
| `-check` prints your own IP | Traffic did not go through the tunnel | You are testing the wrong proxy port, or something else is bound to it. |
| SOCKS5 connects but nothing loads | DNS resolved locally, or the target is blocked outbound | Use `socks5h://`. Then check `journalctl -u chamele0nx-server` for dial failures. |
| Throughput far below the link speed | Congestion control, or the route itself | Section 8. Then measure raw HTTPS from the server and compare; if raw and tunnelled are close, the route is the ceiling, not the protocol. |
| Throughput collapses to near zero under load | Several server instances on one vCPU | Run one. Two competing instances on a single core produce a convincing-looking total failure. |
| Renewal happened, all clients broke at once | New key pair, pinned clients | `reuse_key = True`, section 3. Reissue with `--reuse-key` and redistribute if the key already changed. |

For everything after the first successful connection, read
[OPERATIONS.md](OPERATIONS.md).
