# Threat model

This document states who Chamele0nX is for, what it defends against and by
what mechanism, and — at greater length — what it does not defend against.
The second list is the important one. If you read only one section, read
[What this does not defend against](#what-this-does-not-defend-against).

Nothing here is a promise. Every defence below is a claim about code in
this repository, and each one names the file that implements it so you can
check it yourself. Where something has not been measured, it says so.

---

## Who this is for

**A person in a country that filters the internet, who wants to reach the
ordinary internet, and whose adversary is a national filtering system
rather than a team of people interested in them personally.**

That person's threat is bulk. A filtering system inspects everyone's
traffic with a budget of microseconds per flow, decides "VPN / not VPN"
on cheap features, and applies the same rule to millions of connections.
It is not looking for you. It is looking for a shape. Chamele0nX is an
attempt to not have that shape.

## Who this is not for

**Anyone under targeted surveillance.** If a well-resourced adversary has
decided to learn what *you specifically* are doing, this does not help
you, and believing otherwise is dangerous. Against a targeted adversary
the traffic-shaping defence is close to worthless: they can watch one
user for weeks, correlate the times you are online with events they care
about, subpoena or seize the server, or simply look at the device in your
hand.

**Anyone who needs anonymity from the destination.** Chamele0nX is a
tunnel, not an anonymity network. The server sees every destination you
connect to, and the destination sees the server's address. There is one
hop and it belongs to whoever runs it. If you need the property that no
single party knows both ends, you need Tor, and you need to understand
that Tor makes a different trade — see the [FAQ](FAQ.md).

**Anyone on a network running a strict allow-list.** If the network
permits only a published list of destinations and drops everything else,
a connection to an unlisted host fails no matter how it is shaped.

**Anyone who cannot tolerate being wrong.** This code has had no
independent review. See [Residual risk](#residual-risk).

---

## The adversary

The realistic censor is a national filtering system installed at or near
the operator level, with a live view of every packet crossing its
boundary and a fixed budget per flow. Capabilities differ by country and
often by region within one country. Treat the list below as a menu the
censor picks from, not as a set of things every censor does.

### What the censor does everywhere

**Passive metadata analysis.** The censor reads the parts of a
connection that encryption does not cover: the destination address, the
TLS `ClientHello` (SNI, extension order, cipher list, ALPN), the sizes of
TLS records, the time between them, how they clump into bursts, the ratio
of upload to download, and how long the session lasts. This works on
encrypted traffic because none of it is encrypted — it is the shape of
the ciphertext, not the ciphertext. Published work shows that coarse
features of exactly this kind classify encrypted traffic well
([Dyer et al., IEEE S&P 2012](https://dl.acm.org/doi/10.1109/SP.2012.28);
[Xie et al., USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/xie)).

**Detecting the absence of structure.** A protocol that begins with
uniformly random bytes and no recognisable handshake is itself
distinctive. China's system has classified "fully encrypted" traffic in
real time since 2021 on entropy heuristics alone, without knowing which
protocol it is looking at ([Wu et al., USENIX Security
2023](https://gfw.report/publications/usenixsecurity23/en/)). This is
why "encrypt everything and send it raw" is not a hiding strategy.

**Blocking by address.** The cheapest and most durable action available:
drop everything to an IP address, a prefix, or an autonomous system. It
requires no analysis at all.

**Blocking by name.** Reading the SNI out of a `ClientHello` and dropping
the flow. Extended to QUIC by decrypting the Initial packet, which China
has done at scale since 2024 ([Wu et al., USENIX Security
2025](https://gfw.report/publications/usenixsecurity25/en/)).

### What many censors also do

**Active probing.** After a flow looks suspicious, the censor connects to
the server itself and tries to make it behave like a proxy. This is old,
well documented and effective ([Ensafi et al., IMC
2015](https://dl.acm.org/doi/10.1145/2815675.2815690)), and refusing to
answer probes is itself a fingerprint ([Frolov et al., NDSS
2020](https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/)).

**Volume and duration limits.** Rather than classify a protocol, cut any
single connection that moves more than some number of kilobytes to a
foreign destination — silently, with no reset. Filtering of this kind
against foreign-hosted TLS has been reported in Russia
([net4people/bbs #490](https://github.com/net4people/bbs/issues/490)).
This is arithmetic, not analysis, and no amount of mimicry defeats it.

**Degrading instead of blocking.** Throttle a destination to a few
hundred kilobits rather than dropping it. Users blame their connection,
not the censor, and the tool's authors get no clean signal that they were
detected. Assume this before assuming a network is healthy.

**Allow-listing.** Permit a published set of destinations and drop the
rest, usually regionally and usually temporarily.

### What the censor generally cannot do

It cannot read inside a correctly implemented TLS 1.3 session. It usually
cannot afford to store full packet captures of a whole country for long,
though it can for selected flows. It usually has no vantage point outside
its own borders, so end-to-end correlation across the boundary is
available to only some adversaries. None of these limits is guaranteed,
and the last one is exactly the assumption a targeted adversary breaks.

---

## What this design defends against

Each item names the mechanism and the file that implements it.

**An active prober asking "is this a proxy?"**
Every request that is not an authenticated POST to the configured API
path is served by the cover site handler; an unauthenticated POST to the
API path itself gets a constant `401` JSON error body, and any other method a
`405` with an `Allow` header — the answers a real cookie-protected
endpoint gives, not an error that singles the endpoint out
(`transport/chamele0nx/server.go`, `handleRequest` and `apiDecoy`). The
bodies are constant because a real API's 401 and 405 bodies are constant
too; only the `X-Request-Id` header varies per call. No port, path or
header distinguishes the server from a web server by its presence alone,
and there is no state to reach without the secret.

**An observer looking for a credential in the clear.**
There is no login. Authentication is a rotating token,
`HMAC-SHA256(secret, time_bucket || server_id)`, base64url-encoded and
wrapped in whatever cookie name the cover site's framework would use — a
WordPress login cookie, a Django `sessionid`, or a generic `sid`
(`transport/chamele0nx/auth.go`). A raw hex value in a cookie would itself
be the tell.

**A timing oracle over the server's secret list.**
The server iterates *every* configured secret on every authentication
attempt and never returns early on a match, so total work does not depend
on which secret matched or whether any did; the comparison itself is
`hmac.Equal` (`transport/chamele0nx/server.go`, `authenticateClient`).

**TLS handshake fingerprinting.**
The handshake is generated by uTLS with `HelloChrome_Auto` rather than by
Go's `crypto/tls`, whose fingerprint is distinctive
(`transport/chamele0nx/chamele0nx.go`). A TLS 1.3 session-ticket cache is
shared across reconnects, so a returning client presents a pre-shared-key
extension the way a real browser does instead of always looking like a
first visit (`Transport.sessionCache`).

**HTTP/2 fingerprinting.**
The HTTP/2 layer sends Chrome's four SETTINGS entries in Chrome's order,
Chrome's initial `WINDOW_UPDATE` delta, and Chrome's pseudo-header order
`:method :authority :scheme :path`, which differs from the Go standard
library's (`transport/chamele0nx/chamele0nx.go`, the `http2.Transport`
literal inside `connect`).

**Header and fingerprint mismatch under an authenticated probe.**
The User-Agent pool contains only Chromium-based browsers, because the
HTTP/2 fingerprint above is Chrome's; a Firefox or Safari User-Agent over
a Chrome HTTP/2 stack is a visible contradiction to anyone who can read
the header (`transport/chamele0nx/useragent.go`). Selection is
deterministic per connection, so the value does not change mid-session.

**Record-size and burst-timing classification.**
Outbound data is not written as a flat stream of maximum-size records.
`ShapedConn` samples each record size from the profile's histogram, adds
±25% per-record jitter derived from a per-connection seed, counts records
into bursts sampled from the profile, and sleeps between bursts
(`transport/chamele0nx/shaped_conn.go`, with the size-jitter primitive in
`shaper.go` and the distributions in `profile.go`). Writes below 512
bytes pass through unshaped so HTTP/2 control frames keep their natural
sizes. The server applies the same treatment to the downstream direction
by wrapping accepted connections before handing them to the HTTP/2 server
(`server.go`).

**Correlating two users of the same server to each other.**
The profile is not used as loaded. `PersonalizeFor` jitters the envelope
itself — bucket weights ±20%, records per burst ±30%, inter-burst pause
±50% — deterministically from the per-connection seed, so two users on
one preset produce related but not identical distributions
(`transport/chamele0nx/profile.go`). The SNI choice and the User-Agent are
likewise per-connection. This narrows the correlation; it does not remove
it. See [Known weaknesses](#known-weaknesses-in-the-current-implementation).

**Byte-count cutoffs that ignore content.**
Optionally, the client advertises an SNI drawn from a pool of widely-used
domains observed to pass such filters, while pinning the server's public
key (`transport/chamele0nx/sni_pool.go`; activation in `chamele0nx.go`).
This is available only when the operator supplies a 32-byte SHA-256 pin
of the server's `SubjectPublicKeyInfo`, because the client must skip
hostname verification to do it. Without a pin the client uses the real
SNI and ordinary certificate validation. This defence targets a specific
filter behaviour observed in one country and may stop working without
notice.

**A device that only ever talks to one address.**
`DecoyDriver` makes small background HTTPS requests to popular CDNs,
package indices and documentation sites so the device's outbound
connection pattern is a fan rather than one long-lived tunnel
(`transport/chamele0nx/decoy.go`). Read the caveats below — as shipped,
this is weaker than it sounds.

**Reading the traffic if the outer TLS session is later compromised.**
Tunnel payloads are protected by AES-256-GCM under a key derived with
HKDF-SHA256 from an X25519 exchange performed inside the TLS session, so
the tunnel has forward secrecy independent of the outer TLS
(`transport/chamele0nx/chamele0nx.go`, `deriveSessionKey`;
`internal/chcrypto`).

**Turning the server into an attack tool against its own network.**
The server refuses tunnel targets that resolve to private, loopback or
link-local addresses unless explicitly configured otherwise
(`transport/chamele0nx/server.go`, `validateTargetHost` / `isPrivateIP`).

**Logs that identify users.**
The logging contract limits anything at info level or above to counters
and lifecycle events (`transport/chamele0nx/server.go`). This is a
convention enforced by review, not by the type system.

---

## What this does not defend against

**Blocking the server's address. This is the one that will get you.**
Nothing in this protocol prevents a censor from dropping all traffic to
the server's IP address, and nothing in it helps a user whose server has
been blocked. Every user of that server is offline until someone hands
them a new address out of band. There is no server discovery, no address
rotation and no fallback list in this repository. Traffic shaping buys
time before the address is identified; it does nothing afterwards. If you
deploy this, plan for address replacement as a routine operational event
rather than an emergency.

**Allow-list networks.** If the network forwards only traffic to a
published set of destinations, a well-shaped connection to an unlisted
host is still a connection to an unlisted host. No mimicry defeats an
allow-list. The only answers are to be on the list, which this design
does not attempt, or to have no connection at all.

**A global observer who can see both ends.** An adversary with a view of
your access network *and* of the server's network can correlate the two
sides by timing and volume regardless of what the middle looks like.
Shaping changes the shape identically on both sides, so it does not break
that correlation. This is a known limit of all single-hop tunnels.

**Compromise of the server.** The server terminates your tunnel. It sees
every destination address, every byte at the tunnel boundary, and the
address you connect from. If it is compromised — by an intruder, by the
hosting provider, by seizure — all of that is available. Chamele0nX
protects traffic from the network in between. It does not protect it from
the endpoint.

**Coercion of the operator.** If the person running the server is
identified and compelled, they can log everything, and the protocol
cannot tell you it is happening. If you and the operator are the same
person, note that the server is registered to someone, paid for by
someone, and reachable at an address that appears in someone's records.

**Traffic analysis against a single watched user.** The profile makes
your traffic resemble a plausible distribution of web traffic. It does
not make you resemble *yourself doing something innocent*. An adversary
watching one user over days works with aggregates the shaper does not
control: total daily volume, times of day, session durations, correlation
with external events. A video call is hours of sustained throughput, and
no record-size histogram hides that a lot of data moved.

**Account and identity correlation.** If you sign into the same accounts
through the tunnel that you use without it, the services know, and anyone
with access to those services knows. The transport has no opinion about
what you do inside it.

**Malware or an adversary on your device.** Anything reading the screen,
the keyboard or memory sees plaintext. It also sees the client
configuration, which contains the server address and the shared secret.

**DNS and other traffic outside the tunnel.** The CLI client exposes a
local SOCKS5 proxy. Only what you point at that proxy goes through it.
Applications not configured to use it, and name lookups performed outside
it, take the normal network path. Use `socks5h://` rather than
`socks5://` so names are resolved at the server end.

**Your own operational mistakes.** Sharing a server address in a public
channel, reusing one secret across users you cannot vouch for, or
publishing the traffic profile you run are all faster routes to being
blocked than any classifier.

---

## Known weaknesses in the current implementation

These are specific, current, and in the code as it stands.

**The server's own TLS fingerprint says "Go".** The listener terminates
TLS with Go's `crypto/tls` and no explicit cipher or curve preferences,
so its JARM and JA3S values are those of the Go standard library rather
than of the nginx or Cloudflare front the cover site imitates. Measured
against live hosts, four stacks give four distinct JARM values, and a Go
server is recognisably not nginx. That is a server-side property visible
to anyone who scans the address; no amount of record shaping touches it,
because the answer is decided before any application data is sent.

This cannot be fixed by configuration. The order of extensions in Go's
ServerHello is fixed in the standard library, the TLS 1.3 cipher list is
not configurable, and JARM hashes exactly that. Setting explicit
preferences would move the fingerprint without making it match anything
real — trading a common Go signature for a rare unique one, which is
worse for a scanner.

There is no evidence in the public record of a censor blocking by
server-side JARM or JA3S; documented blocking has been by SNI, by active
probing, and by client-side fingerprints. But `ssl.jarm` is a search
field in Shodan and Censys, so the cost to a censor who wants it is low.

Two mitigations exist, neither of them free. An operator can terminate
TLS with a real nginx or Caddy and forward plaintext to the server, which
buys a genuine front-end fingerprint at the cost of the TLS record
shaping this transport performs on its own connection. The complete
answer is a REALITY-style mode where the server does not terminate its
own TLS at all but forwards an unauthenticated handshake to a real site;
that is a different wire protocol and is on the roadmap, not in this
version.

**The auth token has a five-minute window and is not bound to anything.**
The token is `HMAC-SHA256(secret, floor(unix/300) || server_id)`, and the
server accepts both the current and the previous bucket to tolerate clock
skew (`auth.go`). An observer who obtains a valid cookie — from a
client's memory, a compromised device, or a TLS-terminating middlebox on
the client's side — can replay it from any address for up to about ten
minutes. The token is not bound to the connection, to a channel binding,
to the client's address, or to a nonce. It also does not identify *which*
user connected: it proves only that someone holds one of the server's
secrets.

**The secret is a long-lived bearer credential.** It sits in the client's
configuration in plaintext. Anyone who obtains it is that user.
Revocation means the operator removing it from the server and reissuing
to everyone affected; the protocol has no per-user session state and no
expiry.

**One server serves exactly one domain.** The server takes one
certificate, one key and one cover directory (`ServerConfig` in
`server.go`). It cannot present different sites to different clients, and
the cover site is whatever is in that directory — if it is thin, stale or
obviously a placeholder, a person who looks will notice, and the design
assumes someone eventually looks.

**One profile per server, so a server's users resemble each other.**
`PersonalizeFor` varies the envelope per connection, but every connection
starts from the same profile. A classifier built to find *this protocol*,
rather than VPNs generally, can plausibly learn the family of
distributions that profile generates. How much the personalisation costs
such a classifier has not been measured.

**The uTLS fingerprint ages, and the User-Agent pool ages with it.**
`HelloChrome_Auto` imitates whatever Chrome version the vendored uTLS
release targets, and the User-Agent pool is hard-coded to Chrome 146 and
Edge 147 (`useragent.go`). Real Chrome moves every few weeks. A
once-common fingerprint becomes a rare fingerprint, and rarity is a
signal. Bumping this is a manual task with no alarm attached to it.

**A client without a public-key pin trusts ordinary name validation.**
That is the correct default, but it means the client's protection against
interception is exactly the protection the public CA system gives that
name. With a pin, hostname verification is deliberately skipped and the
pin is the only thing between the client and an impostor — so a stale pin
fails closed, and a pin delivered over an untrustworthy channel is worth
nothing.

**There is no protocol version negotiation.** Frames carry a type and a
length and nothing else (`proto.go`). A client and a server that disagree
about the wire format fail confusingly instead of negotiating down. Every
wire change is a flag day, and mobile clients update slowly.

**Burst pauses are clamped to 250 ms in the write path.** A profile
asking for multi-second pauses does not get them unless it sets
`BypassPauseCap`, because the pause is an inline sleep holding the write
mutex and would stall every other stream on the connection
(`shaped_conn.go`). The shaped output therefore reproduces the short idle
gaps of real browsing and not the long ones.

**Downstream shaping has a kill switch, and it exists because shaping
cost throughput.** `DisableDownstreamShaping` (`server.go`) drops
server-side shaping entirely. It is documented as an escape hatch for
operators whose throughput regresses. A server running with it enabled is
substantially weaker than this document otherwise describes, and nothing
on the wire tells the client which mode the server is in.

**The decoy driver is a no-op unless the client integrates it, and its
TLS fingerprint does not match the tunnel's.** On a mobile client with a
system VPN active, decoy requests are routed *through* the tunnel by
default, which produces the opposite of the intended effect; the native
client must exclude those sockets explicitly. Separately, the driver uses
the Go standard library's TLS by default rather than the uTLS stack the
tunnel uses, so decoy connections and tunnel connections from one device
present different TLS fingerprints — itself a correlatable oddity. Both
facts are documented on `DecoyConfig.HTTPClient` in `decoy.go`; the second
is an unresolved limitation, not a solved problem.

**A shared decoy target list is public by construction.** The five URLs in
`ExampleDecoyTargets` are illustrative, and the driver deliberately does not
fall back to them — but anyone who ships that list unchanged inherits the
problem it exists to warn about: a censor reading this repository knows
exactly which URLs such a device fetches, and the *set* is more distinctive
than any single member of it. Supply hosts you operate.

**The SNI pool is public, fixed and perishable.** Same reasoning. It was
selected from a published measurement snapshot; a domain that stops
passing the filter becomes a liability for anyone still using it, and
nothing in the code notices when that happens.

**Shaping costs throughput and the cost is not accounted for.** The live
write path (`shaped_conn.go`) never pads: it splits writes to fit the
profile's size buckets and inserts the profile's pauses, so the cost is
latency and idle time rather than extra bytes. A write that ends mid
burst still leaves a short tail record, which is itself a small shape
artefact. None of this has been measured across profiles, and nothing
reports it at runtime.

**Throughput figures are the author's, from one path.** Roughly
20 Mbit/s was observed over one long-haul route, and the observation was
route-limited rather than protocol-limited. Nobody has reproduced it.
Treat it as an anecdote.

---

## Operational assumptions

The defences above hold only if all of the following are true. Each is
the operator's responsibility, and the protocol can check none of them.

**The domain looks like something.** A domain registered yesterday, with
no history, hosting a single page, at a provider known for proxies, is
suspicious before a single packet is shaped. Certificate transparency
logs are public and searchable.

**The cover site is a real site.** Not a placeholder, not a default page,
not one file. It should be something a person could land on and believe
in: more than one page, plausible assets, a reason to exist. The premise
of the design is that the server *is* a website that also carries a
tunnel — not a tunnel wearing a website.

**The traffic profile matches the cover.** A profile measured from a
dashboard application, served by a site that looks like a brochure, is a
contradiction available to anyone who fetches both.

**The profile is not published.** A profile is a description of exactly
what your traffic will look like. Publishing yours hands a classifier its
training labels. The examples under `deploy/profiles/` exist to show the
format; a deployment should measure its own.

**The secret has not leaked.** Including into a chat message, a
screenshot, a support ticket, a git repository, or a shell command
visible in a process list.

**The server is not compromised, and is patched.** As above: the server
sees everything.

**Clocks are roughly correct.** Token validation tolerates one window of
skew, five to ten minutes in practice. A device with a badly wrong clock
cannot authenticate.

**The number of users per server is small and known.** Every additional
user adds volume to one address, and volume to one address is one of the
features a censor can act on cheaply.

---

## Residual risk

**No independent audit has been performed.** Nobody outside this project
has reviewed the cryptography, the protocol, or the implementation. The
tests in this repository were written by the same people who wrote the
code. They establish that the code does what its authors intended, which
is a different and much weaker claim than that the design is sound.

**The shaping defence has not been evaluated against a real classifier.**
The repository ships a validator that checks output against a profile
statistically. That is a self-consistency check, not an adversarial
evaluation, and the difference matters: passing your own test says
nothing about a classifier trained specifically to separate this traffic
from the cover it imitates.

**Protocol mimicry has a poor historical record.** Systems that imitated
a protocol from the outside have repeatedly been broken by observers who
compared the imitation against the real thing ([Houmansadr et al., IEEE
S&P 2013](https://www.ieee-security.org/TC/SP2013/papers/4977a065.pdf);
[Wang et al., CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813715)).
This design tries to avoid that failure by *being* a real HTTPS site
rather than imitating one: the site is genuinely served, the certificate
is genuinely valid, the HTTP/2 is genuinely HTTP/2. But the shaping layer
is still an imitation of a measured distribution, and imitations of
distributions have their own history of failing against a stronger
classifier than the one they were tuned for. Assume a sufficiently
motivated adversary can distinguish this traffic, and treat the question
as *how much does it cost them*, not *can they*.

**Report problems privately.** Security issues go through a private
advisory, never a public issue. See [SECURITY.md](../../SECURITY.md).

---

## See also

* [COMPARISON.md](COMPARISON.md) — how this compares to other approaches,
  including where they are better.
* [RESEARCH.md](RESEARCH.md) — the work this design draws on.
* [OPERATIONS.md](OPERATIONS.md) — running a server without undoing the
  above.
* [SPEC.md](SPEC.md) — the wire protocol as implemented.
