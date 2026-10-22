# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), where a
major version change means the wire format changed.

## Unreleased

### Changed
- The client's HTTP/2 stack moved from `github.com/bogdanfinn/fhttp` (which
  carries no licence file) to `github.com/imroc/req/v3` (MIT), and the second
  uTLS fork (`bogdanfinn/utls`) left the module graph with it. The Chrome
  HTTP/2 fingerprint is unchanged: the same four SETTINGS in the same order,
  the same initial WINDOW_UPDATE of 15663105, the same pseudo-header and
  header order. A new test reads the raw connection preface and checks all of
  it.

### Fixed
- `chamele0nx-validator` can pass its own self-test. It compared the sizes a
  profile emits against the histogram those sizes are drawn from *before* the
  shaper's ±25% per-record jitter and its clamping to a legal record length,
  so it reported FAIL for every profile ever shipped — `saas-fast` at
  D ≈ 0.083, `saas-stealth` at D ≈ 0.015, unchanged from three thousand
  samples to three hundred thousand. Both tests now run against the
  distribution a peer actually puts on the wire, so the verdict line and the
  exit code can be used as a regression gate, which is what CONTRIBUTING has
  been telling contributors to do.
- The chi-squared test no longer discards the records it cannot place. Every
  sample that jitter had carried into the gap between two buckets, or past the
  last one, was dropped silently, which pulled the observed counts below the
  expected ones by an amount nothing in the output revealed.
- The self-test judges at α = 1e-4 while comparing real captured traffic keeps
  α = 0.05. In generate mode the samples are drawn from the profile being
  tested, so the null hypothesis is true by construction and the customary
  0.05 guarantees a false alarm about one run in twenty — measured over twenty
  runs of `saas-stealth`, whose p-values came out spread evenly across the
  interval with exactly one below 0.05. A gate documented as a regression
  check cannot fail on schedule, so the self-test asks whether the model is
  broken rather than whether one draw was unlikely. An explicit `-alpha` still
  wins, which keeps the old behaviour one flag away.
- The emitted-size model can no longer hold negative mass. Resolving its range
  additions is a long chain of additions and subtractions that cancel exactly
  in arithmetic but not in floating point, which left a residue of a few times
  1e-18 on sizes no interval covers — enough to put a phantom atom on the
  record ceiling for profiles whose jitter cannot reach it.
- The validator refuses to render a verdict on fewer than 200 samples instead
  of passing them. A gate that says PASS because it was handed too little to
  judge reads as evidence and is worse than no gate at all.
- One stream whose reader stops consuming no longer freezes every other
  connection in the tunnel. Delivery used to block, which stopped the
  dispatcher and the tunnel read loop; on the client nothing ever cleared it.
  A stalled stream is now reset on its own after a short grace period.
- The substitute SNI is chosen once per client instead of afresh on every
  dial. Redrawing it meant session resumption almost never matched, so nearly
  every connection was a full handshake with no ticket, and one address
  claimed two dozen brands in a short window.
- A share link naming the `saas-stealth`, `saas-fast` or `saas-max` profile no
  longer kills the connection. Those are the names of the profiles shipped
  under `deploy/profiles`, and the server side is configured with them, but the
  client had no built-in by any of those names — so the resolver fell through
  to its filesystem-path branch and tried to open a file called `saas-stealth`,
  failing every connect with `load profile: open saas-stealth: no such file
  or directory`. All three names now resolve to a built-in, so a link minted
  from a server profile connects on a client that never had the JSON file.

### Added
- `chameleon_spoof_sni`, so an operator can advertise a name they actually
  control rather than one from the built-in pool. Requires a key pin.
- A cap of 512 concurrent streams per tunnel, and an RST in reply to a
  CONNECT that would exceed it.
- `DefaultSaaSStealthProfile`, `DefaultSaaSFastProfile` and
  `DefaultSaaSMaxProfile`, built-in twins of the
  `deploy/profiles/*.example.json` shapes, resolvable by name through
  `BuiltInProfileByName` (`saas-stealth`/`saas_stealth`, `saas-fast`/`saas_fast`,
  `saas-max`/`saas_max`). They mirror the shipped JSON field for field and are
  deliberately not aliases of the `stealth`/`aggressive` presets or of each
  other, which differ in bucket weights, burst size, pause length and stream
  count. Like the shipped files they are generic example shapes, not measured
  from a real site.
- `deploy/profiles/saas-max.example.json`, a third example profile past the
  fast end of the range: nothing under 2600 bytes, 75–210 records per burst
  and 2–9 ms between bursts. It is the throughput option and the weakest
  disguise of the three, documented as such in both profile guides.

### Changed
- The three example profiles under `deploy/profiles` carry newly authored
  numbers. Different bucket boundaries, different weights, different burst and
  pause ranges — a shape written for the repository to read and edit rather
  than one lifted from a running deployment. Each still serves its stated
  purpose (`saas-stealth` small records and pauses past a second, `saas-fast`
  throughput, `saas-max` more throughput and thinner cover), each still passes
  the validator's self-test, and the built-in twins were updated in step so the
  JSON-versus-constructor comparison still holds them together.
- The `_comment` on each example, and the matching passages in both profile
  guides, now say what these files actually are: illustrations authored for
  this repository, not captured from any site and not measured from real
  traffic. The previous wording claimed as much but the sentence about
  capturing your own read as advice rather than as a condition, so it now says
  plainly that running any of them unmodified means wearing the same
  fingerprint as every other reader of this repository.

### Documented
- The server's own TLS fingerprint is Go's, not the nginx the cover site
  imitates, and Go's ServerHello order cannot be configured to change that.
  Recorded in the threat model with the mitigation and its cost.
- The shipped defaults are a fingerprint shared by every deployment that
  leaves them alone: `-api-path`, `-server-id`, `-cookie-format` and the
  sample cover site. Neither README said so, and the install guide listed
  the defaults without hinting that using them is a decision. Section 6 of
  the install guide now says which to change and what to change them to,
  and the systemd unit says it where an operator copies it from.

### Changed
- The per-record jitter width is one exported constant, `RecordJitterPercent`,
  rather than a literal repeated at each call site. The shaper and the
  validator's reference distribution are now built from the same number and
  cannot drift apart again without a test noticing.
- The stream receive queue is bounded in bytes (1 MiB per stream, 32 MiB per
  tunnel) rather than in frames, and delivery never blocks. Ordinary
  back-pressure no longer resets a healthy connection.

### Corrected in the documentation
- `chamele0nx-validator -generate` reports FAIL on both shipped example
  profiles, and has all along: it applies the live path's ±25% per-record
  jitter and then tests the result against a histogram that does not model
  it. The contributing guide told contributors to use that verdict as a
  regression gate. It now says to read the D-statistic instead, the profile
  guide explains why, and the roadmap carries the defect.
- Six passages still described the cover 404 as an unfixable flaw, after the
  server had learned to serve a cover directory's own `404.html`. The advice
  changes with the fact: ship a 404 page, rather than choose a cover story
  that survives not having one.
- Both specifications listed a per-stream read queue of 64 chunks, which the
  byte budget replaced, and neither listed the 1 MiB, 32 MiB, 512-stream and
  64 KiB header limits at all — the four an independent client discovers as
  unexplained resets. Both architecture documents explained back-pressure in
  terms of the channel that no longer exists.

## v0.1.0 — 2026-09-03

First public release. The protocol works end to end and the documentation
describes what the code actually does, but nobody outside this repository has
reviewed the design or the implementation. Treat it accordingly.

### Added
- `-secret-file` on both the server and the client, so the user secret
  never has to appear in a command line where `ps` can read it. The
  environment variable `CHAMELE0NX_SECRET_FILE` works the same way.
- `-version` on every command, reporting the version, commit and build
  date stamped in at link time.
- Deployment material under `deploy/`: a hardened systemd unit that takes
  the secret through systemd credentials, TCP tuning that switches the
  server to BBR, two example shaping profiles, and a placeholder cover
  site.
- Documentation in English and Russian under `docs/`, including a wire
  format specification, a threat model, and diagrams generated from
  `docs/assets/generate.py`.

### Fixed
- The tunnel API path no longer hands invented data to an anonymous caller.
  It used to answer any unauthenticated request with HTTP 200 and a body of
  made-up events and a cursor that never advanced — the opposite of what a
  cookie-protected endpoint does, and two clean tells at once. It now refuses
  the way the framework named by `-cookie-format` refuses, identically on GET
  and POST, and answers 405 with an `Allow` header on any other method.
- The listener advertises `http/1.1` alongside `h2`. Advertising `h2` alone
  was itself a discriminator: a prober offering only HTTP/1.1 drew
  `no_application_protocol` where a real site would have answered.
- Secret matching no longer returns early. Stopping at the first match made
  the time taken depend on which secret matched, which a patient attacker can
  measure; every secret is now checked on every attempt.
- The session key is no longer wiped while other goroutines are encrypting or
  decrypting with it — a data race on key material, reachable whenever a
  tunnel closes while relay handlers are still draining.
- Random durations are drawn in 64-bit arithmetic. On a 32-bit build any span
  wider than about two seconds overflowed and collapsed to its minimum, so
  shaping pauses became a constant on targets such as android/arm.
- A repeated CONNECT for an open stream ID closes the displaced stream instead
  of abandoning its relay goroutine and TCP connection until the idle timeout.
- The built-in cover site no longer reports a hardcoded version and an
  uptime derived from the wall clock. Both were identical on every
  deployment at any instant, which made a single request to
  `/api/v1/health` a reliable way to find every server running this
  software. They are now drawn per server at startup.
- An unauthenticated request can no longer buy unbounded work. The number
  of cookie segments and candidate tokens examined is capped, tokens of the
  wrong length are rejected before any HMAC is computed, and the HTTP/2
  header limit is 64 KiB rather than the 1 MiB default. Constant-time
  behaviour is unchanged.
- A cover directory containing `404.html` now serves it for unknown paths.
  Previously those got Go's plain-text "404 page not found", so a cover
  site answered as two different applications.
- The install guide's verification step described the decoy endpoint's old
  behaviour (200 with invented events) rather than what the server does
  (401, and 405 with an `Allow` header). The Russian specification stated
  the wrong ALPN list and omitted the paragraph explaining the
  active-probe defence behind it. Both are corrected, along with the decoy
  target count, a `Connection: close` instruction that is illegal under
  HTTP/2, and four references to a `FIXME` that does not exist.

### Changed
- The module is now `github.com/meshoklv/chamele0nx` and contains
  only the Chamele0nX transport. Dependencies dropped from around sixty to
  five direct ones.
- `github.com/klauspost/compress` raised to v1.18.7, which clears
  GO-2026-5841. The affected code was never reachable from here.
- `scripts/check-no-private-data.sh` now also catches credential-shaped
  strings, e-mail addresses, routable IPv6, Windows and personal paths,
  single-label hostnames, and anything of that shape anywhere in the commit
  history — not only in the current tree.
- Cryptographic helpers moved to `internal/chcrypto`. Unused key
  derivation for other protocols was removed.

### Removed
- Code that nothing used. Two writers that emitted TLS records and bursts
  with random padding were only ever called by their own tests, while the
  live connection path pads nothing, so they are gone along with the
  padding they implied. A taxonomy of censorship environments, with a
  preference map from network class to cover, went with them: nothing in
  the project measured a network to produce a class, and with a single
  registered cover every class resolved to the same answer. The sampled
  burst those writers consumed stays, because the profile validator still
  builds one.
- The embedded certificate public-key pin for the author's own server,
  and the branch that installed it automatically for one hard-coded
  domain. Pinning is still supported through the
  `chameleon_pubkey_pin` endpoint parameter, which is now the only way to
  enable SNI spoofing.

### Fixed
- A data race between the tunnel's per-stream goroutines and its HTTP
  handler. The handler could return while a relay goroutine was still
  writing into the `http.ResponseWriter`, which is not allowed and which
  the race detector caught on every run. The handler now takes the write
  mutex before it declares itself finished, so it waits for any write
  already under way and later writes fail cleanly instead.
- A `PING` frame from a client hit an unchecked type assertion on the
  request body, which does not implement `io.Writer`. Any client that
  sent one crashed its own tunnel handler. Pongs now go out through the
  same guarded writer as everything else.

### Security
- Upgraded `golang.org/x/net` and `golang.org/x/text`. The versions the
  code was pinned to carried two vulnerabilities that our own call paths
  reach: an infinite loop on invalid input in text normalisation, and a
  failure to reject certain Punycode labels. `govulncheck` reports none
  after the upgrade, and CI now fails the build if that changes.
- Nothing in this repository refers to a live deployment: no domains, no
  addresses, no certificate pins, no captured traffic profiles.
- `TimeoutStopSec` in the shipped unit was shorter than the server's own
  30-second drain, so systemd killed tunnels that the server was still
  closing cleanly. Raised to 40 seconds.

## Wire format history

The frame and stream layers have not changed since UDP support was added
(stream types `0x05` and `0x06`). A server carrying that support accepts
clients that only ever send TCP stream types, so the addition was
backward compatible.
