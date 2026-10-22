# Operating a Chamele0nX server

[INSTALL.md](INSTALL.md) gets a tunnel working. This document is about
keeping it working without burning yourself or the people using it.

Read [THREAT-MODEL.md](THREAT-MODEL.md) first. It says what the protocol
does not protect against. Most of what follows exists because the
protocol is not the weakest part of a deployment.

---

## The operator is part of the attack surface

The protocol hides the traffic. It does not hide you. An adversary who
cannot classify your packets can still take the shortest path available,
and the shortest path is usually administrative rather than technical.

| Surface | What goes wrong |
|---|---|
| **SSH access** | A key that also unlocks ten other machines turns one compromised laptop into a compromised fleet. A password-authenticated root login is brute-forced within days of the host coming online. |
| **The hosting panel** | Whoever controls it can reboot into a rescue image and read the disk. That is not an exotic attack; it is a support feature. Assume the disk is readable by the provider. |
| **The domain registrar** | Control of the domain is control of where clients connect. Registrar account takeover redirects your users without touching your server. |
| **Payment trail** | The card, the invoice and the billing address link the server to a person. This is generally the easiest link in the chain to follow, and no amount of traffic shaping affects it. |
| **The server's own view** | The server dials the destinations your users ask for. It can see them. What it logs is your decision; see "What to log". |
| **Your other identities** | Registering the domain, paying for the VPS and administering the box from the same account, network or browser profile ties them together. |

None of this is unique to Chamele0nX. It is listed because operators
routinely spend a week on protocol details and five minutes on the SSH
configuration.

---

## Server hardening checklist

Do all of these. They take about fifteen minutes on a fresh host.

**Keys only, no passwords.**

```bash
sudo tee /etc/ssh/sshd_config.d/00-hardening.conf >/dev/null <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
sudo systemctl restart ssh
```

Check that no other file re-enables it. Cloud images frequently ship
`/etc/ssh/sshd_config.d/50-cloud-init.conf` with `PasswordAuthentication
yes`, and the last matching directive wins:

```bash
sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin'
```

Verify from another machine before you close your session. Locking
yourself out of a censorship-resistant server is an ordinary way to lose
one.

**If the provider emailed you a root password, change it.** It exists in
their mail system and in yours. Change it even if you disable password
login, because the provider's rescue console still accepts it.

**Firewall default deny.** Section 7 of INSTALL.md. Confirm it survives a
reboot; rules that live only in memory are not a firewall.

```bash
sudo ufw status verbose        # want: Status: active, default deny (incoming)
```

**Automatic security updates.**

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

Take security updates. Be deliberate about full upgrades: anything that
restarts the network stack drops every active tunnel.

**Rate-limit SSH brute force.**

```bash
sudo apt install -y fail2ban
```

**No memory dumps, no ptrace.** Session keys and the secret live in
process memory. A core dump written to disk, or a debugger attached by
another process, hands them over.

```bash
sudo tee /etc/sysctl.d/99-chamele0nx-hardening.conf >/dev/null <<'EOF'
kernel.yama.ptrace_scope = 2
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
sudo sysctl --system
```

The shipped systemd unit already sets `LimitCORE=0` and blocks the debug
syscall group; these sysctls close the same door for everything else on
the box.

**A dedicated unprivileged user.** `User=chamele0nx`, no shell, no home
directory that matters. Never run the server as root. Binding `:443`
without root is handled by `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

**File permissions.**

| Path | Owner | Mode |
|---|---|---|
| `/usr/local/bin/chamele0nx-server` | `root:root` | `0755` |
| `/etc/chamele0nx/secret.cred` | `root:root` | `0600` |
| `/etc/chamele0nx/secret` (plain fallback) | `chamele0nx:chamele0nx` | `0600` |
| `/etc/chamele0nx/tls/` | `root:chamele0nx` | `0750` |
| `/etc/chamele0nx/tls/privkey.pem` | `chamele0nx:chamele0nx` | `0600` |
| `/etc/chamele0nx/tls/fullchain.pem` | `chamele0nx:chamele0nx` | `0640` |
| `/var/www/cover/` | `chamele0nx:chamele0nx` | `0755` |
| `/var/log/chamele0nx/` | `chamele0nx:chamele0nx` | `0750` |

Audit the sandbox after any unit change:

```bash
systemd-analyze security chamele0nx-server
```

**Naming.** Nothing on the box has to announce what it is. A binary, a
unit and a directory named after this project tell anyone who gets a
shell exactly what they found. Neutral names cost nothing.

---

## Domain and certificate hygiene

**The domain has to look ordinary.** It is the first thing an analyst
looks at and the cheapest thing to judge. A domain registered last week,
with privacy protection, no mail records, no history and a single page
behind it, is a pattern that gets flagged on its own merits, whatever the
traffic looks like.

What helps:

- register it well before you need it, and let it sit;
- give it the DNS records a real site has, and nothing exotic;
- host something on it that a person would plausibly visit, from the
  first day, not a placeholder you mean to replace later;
- match the cover site to the name;
- keep the registrar account behind its own strong credentials and
  second factor, because losing it loses everything downstream.

**Certificates.** Use a public CA. Let's Encrypt is fine and universal.
Renewal is automatic; what is not automatic is the server picking up the
new file, so keep the deploy hook from INSTALL.md section 3 and confirm
it has actually run at least once:

```bash
sudo journalctl -t chamele0nx-renew --no-pager | tail
sudo certbot certificates
systemctl list-timers certbot.timer
```

**Key reuse and pinning.** If any client pins the certificate public key,
renewal must reuse the key or every pinned client breaks at once. Set
that up before you hand out clients: INSTALL.md, "Key reuse on renewal".
Here the job is only to confirm it held. Compare the fingerprint after
each renewal against the one your clients pin:

```bash
openssl x509 -in /etc/chamele0nx/tls/fullchain.pem -pubkey -noout \
  | openssl pkey -pubin -outform der | sha256sum
```

Do not force renewals to "refresh" things. Public CAs rate-limit issuance
per domain per week, and burning that budget during an incident is how a
recoverable outage becomes a long one.

---

## What to log, and what never to log

The server's default logging is deliberately thin: operational events and
counters, no identities. Keep it that way.

**Log freely:** service start and stop, listen address, configuration
echo, tunnel established and closed counts, error and panic traces,
resource usage.

**Never log:**

| Never | Why |
|---|---|
| Client IP addresses | The single most useful record for anyone attacking your users, and the first thing subpoenaed or seized. |
| Destination hosts and addresses | Reveals what users browse. Equivalent to a browsing history. |
| Cookies or auth tokens | A live credential written to disk, and to your journal, and possibly to a remote log collector. |
| The secret, in any form | Including in a crash trace or a debug dump. |
| Which SNI or cover a client chose | Fingerprints the user across sessions. |
| Full request headers | Contains user agent, cookie and more, all at once. |

**Debug level is not safe in production.** At `-log-level debug` the
server logs the destination address of failed dials and blocked targets.
That is user browsing data. Debug level is for a local reproduction, not
for a running service. Production should be `info`, or `warn` if you want
less.

**Cap the journal**, so logs do not accumulate for years:

```bash
sudo tee /etc/systemd/journald.conf.d/chamele0nx.conf >/dev/null <<'EOF'
[Journal]
SystemMaxUse=200M
MaxRetentionSec=7day
EOF
sudo systemctl restart systemd-journald
```

If you have no reason to keep logs at all, keep less. Logs you did not
write cannot be taken from you.

---

## Rotating a secret

**What the shipped server supports.** The protocol core validates a
client token against every configured secret, in constant time, without
revealing which one matched. The CLI, however, registers exactly one
secret per process. So a single running server has one live secret, and
changing it is a hard cutover: the moment the new secret is loaded, every
client still holding the old one stops authenticating and starts getting
the cover site.

That means you cannot rotate in place without an interruption. You can
rotate without cutting anyone off, by overlapping two endpoints.

**Overlapping rotation, in order:**

1. Generate the new secret. `openssl rand -hex 32`.
2. Bring up a second listener holding the new secret: another instance on
   a second port or, better, a second host with its own name and
   certificate. Give it its own `-server-id`, because the id is mixed
   into the auth token.
3. Hand the new endpoint to clients. Give them time. Assume some will not
   update for weeks.
4. Watch the old endpoint until its tunnel-established count goes to
   zero and stays there.
5. Only then retire the old secret, and only then reuse the port.

**Never reverse steps 3 and 5.** Removing the old secret before clients
have moved is how you lock out exactly the users who cannot easily reach
you to be told what happened.

**Rotate for a reason, and rotate fully.** If the secret leaked, changing
it is not enough on its own: whatever leaked it may also have leaked the
SSH key, the certificate private key and the hosting credentials. Treat
anything that sat on the same machine as compromised.

The client binary necessarily contains the secret it uses. That is
inherent to a symmetric, one-click client, and it means any distributed
client can be unpacked by whoever receives it. Distribution scope is part
of your threat model, not an implementation detail.

---

## If an address gets blocked

**First, establish what is actually blocked.** The instinct is to blame
the software. Usually the address is simply on a list.

Diagnose from inside the affected country, not from your own network. A
server that answers you perfectly can be entirely unreachable for the
people it exists for. You need a probe on the far side: a user willing to
run two commands, a cheap VPS in the region, or any shell you can reach
there.

From inside the affected network:

```bash
# Does the name still resolve, and to the right address?
dig +short vpn.example.com

# Does TCP complete at all?
nc -vz -w 5 vpn.example.com 443
nc -vz -w 5 vpn.example.com 22

# Does the TLS handshake complete, and with which certificate?
echo | openssl s_client -connect vpn.example.com:443 -servername vpn.example.com
```

Then separate the three cases:

| Observation | Conclusion |
|---|---|
| No TCP handshake to any port on that IP, from that country, while other hosts are reachable | The **address** is blocked. |
| TCP completes, TLS fails or resets only for this hostname, and works for another name on the same IP | The **domain or SNI** is blocked. |
| Everything completes but the tunnel does not carry traffic | Not a block. A configuration or service problem; go back to the INSTALL troubleshooting table. |
| Connections succeed briefly, then stall for a couple of minutes, repeatedly | Behavioural throttling rather than a static list. Different problem, different fix. |

**What does not help.** Moving to another port: filtering by address does
not care about the port. Reinstalling the operating system: the address
stays the same. Changing the cover site or the profile: the block was
applied before any of that was inspected. A new certificate: same. Each
of these costs an evening and changes nothing.

**What does help.** A new address. Preferably at a different provider and
in a different autonomous system, because blocks are often applied to
ranges rather than single addresses, and being a neighbour of a burned
subnet is enough. Keep the domain if only the address was blocked; move
the `A` record and clients follow. If the domain itself was blocked, the
domain is the thing to replace.

**Before you migrate**, verify the candidate address from inside the
target country: that it is reachable at all, and how fast it is. Testing
after the move is testing on your users.

**Assume addresses are consumable.** Plan for replacement rather than
permanence: keep the deployment reproducible, keep backups current, and
do not build anything that hard-codes a single address in a place you
cannot update.

---

## Capacity and speed

**The route is almost always the ceiling, not the protocol.** Measured on
a real long-haul path from a censored network: the tunnel ran at
essentially the same speed as plain HTTPS from the same server, meaning
protocol overhead was close to negligible. Four parallel connections
totalled no more than one. The server's own uplink tested at hundreds of
megabits. The limit was the transit between the two countries.

Measure in this order, and stop when you find the answer:

```bash
# 1. Baseline: the client's link, not through your server at all.
curl -o /dev/null -w '%{speed_download}\n' https://speed.cloudflare.com/__down?bytes=25000000

# 2. Raw HTTPS from your server, no tunnel. This is the route's ceiling.
curl -o /dev/null -w '%{speed_download}\n' https://vpn.example.com/<a large static file>

# 3. Through the tunnel.
curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{speed_download}\n' \
  https://speed.cloudflare.com/__down?bytes=25000000
```

If 2 and 3 are close, the protocol is not your problem and no amount of
profile tuning will change it. If 2 is far below 1, the path is the
problem: fix congestion control first, then consider a better-connected
location.

**Congestion control is the highest-value change.** Switching from CUBIC
to BBR with larger buffers moved one such path from 3.5 to 22 Mbit/s,
measured as raw HTTPS to the server rather than through the tunnel.
That is a multiple, not a percentage, and it costs one file. See INSTALL
section 8.

**Shaping profile trades speed against camouflage.** A more aggressive
profile with shorter pauses moves more data and gives a classifier more
regular timing to work with. The two shipped examples make that trade
explicit: `saas-fast` for throughput, `saas-stealth` for cover. Pick
deliberately, and re-check with `chamele0nx-validator` after changing one.

`-disable-downstream-shaping` exists as an emergency switch, not a
performance setting. On the path above it did not help, because shaping
was not the bottleneck. Turning it on removes the defence the project is
built around.

**Do not run several instances on one core.** On a single-vCPU host, two
server processes competing produce a total collapse that looks exactly
like a broken deployment, and it wastes hours. One instance per host.
When A/B testing profiles, run the experiment on a second, temporary
listener and remove it afterwards, and never point it at the port
production is on.

**Restarts are not free.** A restart drains active tunnels for up to 30
seconds and then closes them. Clients reconnect on their own with
backoff, but users see it. Batch your changes.

---

## Backups and recovery

A Chamele0nX server holds very little irreplaceable state. Back up that
little, and rebuilding is a fifteen-minute job.

| What | Why it matters | How to keep it |
|---|---|---|
| **The secret, in plaintext hex** | Lose it and every client must be reconfigured. | Offline, encrypted, off the server. Not in a repository. |
| **The systemd unit** | Encodes every runtime flag you settled on. | Keep it in a private repository alongside your notes. |
| **The traffic profile JSON** | Your speed and camouflage trade-off. | Same place. |
| **The cover site** | Recreating a convincing one takes longer than anything else here. | Same place, or a tarball. |
| **`/etc/letsencrypt`** | Avoids reissuing under rate limits, and preserves the key if you pin. | Encrypted archive, off the server. |
| **The server binary or its exact version tag** | Lets you rebuild the same thing rather than a newer one mid-incident. | Record the version; the source is in git. |

Do not back up `secret.cred` and expect it to work elsewhere. It is
encrypted against the host it was created on; on a new machine it is
noise. Back up the plaintext and re-encrypt on the new host.

Recovery on a fresh box is the INSTALL path with two substitutions:
restore `/etc/letsencrypt` instead of issuing a certificate, and restore
the secret instead of generating one. If the address changed, update the
`A` record and wait out the TTL. If the address changed because the old
one was blocked, see the section above before you assume the new one will
last.

Test the restore once, on a scratch VPS, before you need it. An untested
backup is a belief, not a backup.

---

## Updating

```bash
# 1. Build the new binary, keep the old one.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags "-s -w" -o chamele0nx-server-new ./cmd/chamele0nx-server
scp chamele0nx-server-new root@vpn.example.com:/tmp/

# 2. On the server: keep a rollback copy, note what you are replacing.
sudo cp /usr/local/bin/chamele0nx-server /root/chamele0nx-server.$(date +%F).bak
sha256sum /root/chamele0nx-server.$(date +%F).bak
/usr/local/bin/chamele0nx-server -version

# 3. Swap and restart.
sudo install -o root -g root -m 0755 /tmp/chamele0nx-server-new /usr/local/bin/chamele0nx-server
sudo systemctl restart chamele0nx-server

# 4. Confirm, from the outside as well as the inside.
systemctl status chamele0nx-server
journalctl -u chamele0nx-server -n 50 --no-pager
curl -sS -o /dev/null -w 'HTTP=%{http_code}\n' https://vpn.example.com/
```

A restart is the only downtime: SIGTERM drains in-flight tunnels for up
to 30 seconds, then closes them, and clients reconnect on their own.
There is no zero-downtime upgrade in a single-process deployment. If you
cannot accept the gap, run a second endpoint and move clients across, the
same shape as the rotation procedure above.

**Rolling back** is copying the saved binary back and restarting. Keep at
least one previous version on the box, and record its checksum, so you
are not deciding what to restore in the middle of an outage.

Read the release notes before updating a working server. A change to the
default profile, the cookie format or the API path changes what clients
must send, and mismatched clients get the cover site instead of a tunnel,
which reads as a total failure from the user's side.
