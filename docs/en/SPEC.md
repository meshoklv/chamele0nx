# Chamele0nX Protocol Specification

Status: descriptive. This document describes the protocol **as implemented** in
`transport/chamele0nx` and `internal/chcrypto` in this repository. It is not a
design document: where the code and an older design note disagree, the code wins
and this specification follows the code.

---

## 1. Scope and conventions

### 1.1 Scope

This document specifies:

* the transport establishment sequence (TCP → TLS → HTTP/2 → tunnel);
* the authentication token and its cookie encodings;
* the key exchange and the record protection envelope;
* the frame layer and the stream (multiplexing) layer;
* UDP carriage over the tunnel;
* the traffic-shaping profile format and the shaping algorithm;
* server behaviour toward unauthenticated requests;
* the numeric constants that both peers must agree on.

Out of scope: build and deployment instructions (`docs/en/INSTALL.md`), the
adversary model and what the protocol does **not** defend against
(`docs/en/THREAT-MODEL.md`), and the reconnect/backoff policy of
`PersistentClient`, which is a client implementation strategy and not part of
the wire contract.

### 1.2 Requirement levels

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119. A requirement stated here reflects what the reference
implementation does or enforces; where the reference implementation is
permissive but interoperability depends on the behaviour, this is marked
explicitly.

### 1.3 Byte order and encodings

* All multi-byte integers in Chamele0nX's own framing are **big-endian**
  (`encoding/binary.BigEndian` throughout `proto.go` and `mux.go`).
* Authentication tokens are **base64url without padding**
  (`base64.RawURLEncoding`).
* The `user_secret` endpoint parameter is **lowercase or uppercase hex**; it is
  hex-encoded so it survives a JSON round trip through mobile bindings and
  invite blobs.
* The public-key pin (`chameleon_pubkey_pin`) is **hex**, decoding to exactly
  32 bytes.
* Profile JSON durations are integers in **milliseconds**
  (`DurationRange.MarshalJSON` / `UnmarshalJSON`).

### 1.4 Versioning of this document

This document tracks the source tree it ships with. There is **no in-band
protocol version number** on the wire (see §12); the only versioned artifact is
the traffic profile (`SiteProfile.Version`, currently `1`). Consequently the
authoritative version of this specification is the repository revision that
contains it: this document describes the code as of the commit it ships in.

---

## 2. Layer model

![Wire format](../assets/en/04-wire-format.svg)

From the outside in, one Chamele0nX session is:

```
  TCP  :443
   └── TLS 1.3  (uTLS, Chrome ClientHello; ALPN "h2")
        │        records are size- and timing-shaped (ShapedConn, §9)
        └── HTTP/2  (single POST, request body = upstream, response body = downstream)
             └── Chamele0nX frames        [type:2][length:4][payload:N]   (§6)
                  ├── KEY_EXCHANGE  — X25519 public keys, plaintext      (§5)
                  └── DATA          — AES-256-GCM(nonce ‖ ct ‖ tag)      (§5)
                       └── stream frame  [stream_id:4][stream_type:1][data:N]  (§7)
                            ├── CONNECT / CONNECT_UDP  [host_len:1][host][port:2]
                            ├── DATA      — TCP byte-stream fragment
                            ├── DATAGRAM  — exactly one UDP datagram
                            └── FIN / RST — stream teardown
```

The client exposes the tunnel to applications as a loopback **SOCKS5** proxy;
the server terminates each stream as an outbound TCP or UDP socket.

Layer responsibilities are strictly separated:

| Layer | Provides | Does not provide |
|---|---|---|
| TLS (uTLS) | masquerade, transport security of the cover | confidentiality of the tunnel payload (Chamele0nX adds its own) |
| ShapedConn | record sizes, burst timing | any framing or integrity |
| HTTP/2 | a long-lived bidirectional byte pipe over one POST | flow separation between tunnelled connections |
| Frame layer | delimitation, type dispatch | encryption |
| Record protection | confidentiality and integrity of stream frames | replay ordering across frames |
| Stream layer | multiplexing, per-connection lifecycle | congestion control, per-stream flow control |

---

## 3. Transport establishment

The whole sequence below is implemented inline in `Transport.connect`
(`chamele0nx.go`). See the note in §10.3 about `CoverProfile.Open`.

### 3.1 Endpoint parameters

| Param | Required | Default | Meaning |
|---|---|---|---|
| `chameleon_addr` | yes | — | server `host:port` |
| `user_secret` | yes | — | hex, MUST decode to ≥ 16 bytes (`minUserSecretBytes`) |
| `chameleon_sni` | no | host part of `chameleon_addr` | real SNI |
| `chameleon_path` | no | `/api/v1/events` | HTTP/2 request path |
| `chameleon_cookie` | no | `generic` | cookie format: `generic`, `wordpress`, `django` |
| `chameleon_profile` | no | `DefaultSaaSProfile` | built-in preset name, or a filesystem path to profile JSON |
| `server_id` | no | `endpoint.ID` | server identifier bound into the auth token |
| `chameleon_pubkey_pin` | no | — | hex, exactly 32 bytes; enables SNI substitution |
| `chameleon_spoof` | no | — | `off` hard-disables SNI substitution |
| `chameleon_spoof_sni` | no | pool pick | the name to advertise in substitution mode; requires `chameleon_pubkey_pin` |
| `cover` | no | `saas-http2` | cover profile ID; validated at parameter-check time |

`validateChamele0nXParams` rejects a missing address, a missing or non-hex
`user_secret`, a `user_secret` shorter than 16 bytes, and an unregistered
`cover` ID. A malformed `chameleon_pubkey_pin` is rejected inside `connect`.

### 3.2 Per-connection seed

`connect` draws a 64-bit `clientSeed` from `crypto/rand`
(`generateClientSeed`; it panics if the system RNG fails). This one seed drives
every per-connection choice: substitute-SNI selection, User-Agent selection, profile
personalization, and per-record size jitter. Using one seed is deliberate — the
session presents a single coherent synthetic identity rather than independent
random choices per dimension.

### 3.3 TLS

The TLS handshake uses `github.com/refraction-networking/utls` with the
ClientHello preset **`utls.HelloChrome_Auto`** (`dialUTLSWith`). TCP dial
timeout is 15 s.

`newUTLSConfig` sets exactly three fields, all load-bearing:

| Field | Value | Reason |
|---|---|---|
| `ServerName` | advertised SNI (real or substituted) | what ClientHello carries |
| `ClientSessionCache` | LRU, 32 entries, shared per `Transport` | a real Chrome presents a TLS 1.3 session ticket on reconnect; without a cache every reconnect is a full handshake, which is itself a mismatch against the Chrome fingerprint the rest of the stack emits |
| `DynamicRecordSizingDisabled` | `true` | MUST be true. Otherwise the TLS layer ramps record sizes 512 B → 16 KB over the first ~128 KB, underneath the shaper, which cannot compensate |

After the handshake the client asserts the negotiated ALPN protocol is `h2` and
closes the connection otherwise. Successful handshakes are counted, split by
`state.DidResume`, and readable via `Transport.HandshakeStats`.

The server (`ListenAndServeTLS`) listens with `MinVersion: TLS 1.2`,
`NextProtos: ["h2", "http/1.1"]` and `DynamicRecordSizingDisabled: true`, and
gives each accepted connection 15 s to complete the handshake before it is
dropped. Both protocols are offered because a real site almost always agrees to
HTTP/1.1, so advertising `h2` alone is a discriminator: a prober that offers only
http/1.1 draws `no_application_protocol` from an h2-only server while a real site
answers. `h2` stays first, so the tunnel client (which offers both, h2 preferred)
still lands on h2; the http/1.1 path only ever carries cover-site traffic, never
the tunnel.

### 3.4 SNI, and the substitution mode

Two modes, selected in `connect`:

**Normal.** The advertised SNI and the HTTP/2 `:authority` both equal the real
SNI. Certificate validation is standard.

**Pinned substitution.** Activated only when `chameleon_pubkey_pin` is present and
`chameleon_spoof` is not `off`. Then:

1. the SNI is `chameleon_spoof_sni` when the operator supplied one, otherwise
   `pickSubstituteSNI(identity)` — a pick from `substituteSNIPool`
   (`sni_pool.go`, 31 entries) keyed on `user_secret` and `chameleon_addr`;
2. the HTTP/2 `:authority` and `Request.Host` are set to that **same** substituted
   name, so the inside-TLS layers stay consistent with ClientHello;
3. `InsecureSkipVerify` is set and hostname verification is therefore skipped;
4. a `VerifyPeerCertificate` callback parses the first peer certificate, marshals
   its public key to DER `SubjectPublicKeyInfo`, takes SHA-256, and compares it
   against the pin with `crypto/subtle.ConstantTimeCompare`. A mismatch, an
   empty chain, or a parse failure aborts the handshake.

The SNI choice MUST be stable, and not only for the lifetime of one
connection: it is derived from the client's own identity, so it is the same on
every reconnect for as long as the credentials and the server address stay the
same. Two users of one server land on different names, so a fleet still
spreads across the pool.

An earlier revision drew the name from the per-connection seed, which changed
it on every dial. That was worse than a fixed choice on two counts. The TLS
session cache is keyed by server name, so with 31 names a resumption ticket
matched roughly one dial in 31 and nearly every connection became a full
handshake with no ticket — the very absence the transport works elsewhere to
avoid. And one address answering to two dozen well-known brands in a short
window is a stranger shape than one address that consistently claims a single
name. No comparable transport rotates: REALITY, Trojan and NaiveProxy each pin
one name for the life of a deployment.

An operator who controls a name — one that resolves to them, or one their own
front terminates — should set `chameleon_spoof_sni` to it. That is strictly
better than any pool entry, because the pool names resolve to infrastructure
the operator does not run.

A pin is mandatory for substitution: without it, name verification is left on and
the handshake would fail on the SAN mismatch. Substitution without a pin is not
offered, because disabling name verification with nothing in its place would
make the client trivially interceptable.

### 3.5 HTTP/2

The client uses `github.com/imroc/req/v3` (MIT), not the standard library,
in order to emit Chrome's HTTP/2 fingerprint. The settings below are exact
values from `newChromeH2Transport`:

| Setting | Value |
|---|---|
| `SETTINGS_HEADER_TABLE_SIZE` | 65536 |
| `SETTINGS_ENABLE_PUSH` | 0 |
| `SETTINGS_INITIAL_WINDOW_SIZE` | 6291456 |
| `SETTINGS_MAX_HEADER_LIST_SIZE` | 262144 |

Four settings, in exactly that order (`SetHTTP2SettingsFrame` takes an ordered list).
`SETTINGS_MAX_CONCURRENT_STREAMS` and `SETTINGS_MAX_FRAME_SIZE` are deliberately
**absent** — Chrome does not advertise them.

| Transport field | Value |
|---|---|
| `ConnectionFlow` | 15663105 (the initial `WINDOW_UPDATE` delta Chrome emits after SETTINGS) |
| `InitialWindowSize` | 6291456 |
| `HeaderTableSize` | 65536 |
| `AllowHTTP` | false |
| `DisableCompression` | true |
| `ReadIdleTimeout` | 15 s |
| `PingTimeout` | 5 s |

**Pseudo-header order** (`PseudoHeaderOrder`, and `PHeaderOrderKey` on the
request):

```
:method  :authority  :scheme  :path
```

This differs from the standard library order (`:method :scheme :authority
:path`) and is the single most load-bearing item in the list — it is a
well-known fingerprinting discriminator.

**Regular header order** (`HeaderOrderKey`):

```
cookie  content-type  accept  user-agent
```

**The request:**

| Field | Value |
|---|---|
| Method | `POST` |
| Scheme | `https` |
| Path | `chameleon_path` (default `/api/v1/events`) |
| `:authority` / `Host` | substituted SNI in substitution mode, real SNI otherwise |
| `Cookie` | `FormatCookie(token, cookieFormat)` — §4 |
| `Content-Type` | `application/json` |
| `Accept` | `application/json` |
| `User-Agent` | `pickUserAgent(clientSeed)` — 5-entry Chromium-only pool (`useragent.go`) |

The User-Agent pool contains only Chromium-based strings (Chrome on
Windows/macOS/Linux/Android, Edge on Windows) because a Firefox or Safari UA
combined with Chrome's HTTP/2 settings is a self-inconsistency visible to any
active prober holding a valid token. The pool is version-pinned and MUST be
refreshed as Chrome's major version rolls; a stale pool becomes a fingerprint in
its own right.

**Bodies.** The single POST is the whole tunnel:

* **request body** — client → server, fed from an `io.Pipe` writer;
* **response body** — server → client, read as a stream.

The client requires HTTP status **200**; any other status aborts the connect.
The server sets `Content-Type: application/json`, writes `200`, and flushes
before the key exchange so the response body starts streaming immediately
(`handleTunnel`); every subsequent server write is flushed (`flushWriter`).

### 3.6 Record shaping placement

The dialer returns the uTLS connection wrapped in `ShapedConn`
(§9). The wrapper MUST sit between the TLS layer and the HTTP/2 framer: the
HTTP/2 writer's buffers are what gets re-cut into records, and the TLS layer
below must not re-fragment them. This seam is the reason the implementation
drives uTLS directly instead of using a TLS-client library that owns the TLS
layer internally.

---

## 4. Authentication

### 4.1 Token

```
bucket = floor(unix_seconds / 300)
token  = base64url_nopad( HMAC-SHA256( user_secret, ASCII("<bucket>|<server_id>") ) )
```

Notes on the exact input: the HMAC message is the decimal bucket, a single
`|` byte, and the server ID, formatted with `fmt.Sprintf("%d|%s", bucket,
serverID)` (`generateTokenForBucket`). The output is the raw 32-byte MAC,
base64url-encoded **without padding** (43 characters).

* Window (`tokenWindow`) is **5 minutes** = 300 s.
* The token therefore rotates every 5 minutes and an observed token cannot be
  replayed beyond the next window boundary.
* `ValidateAuthToken` accepts a token whose bucket equals the server's
  **current** bucket or the **immediately previous** one. The tolerance is
  therefore asymmetric: a client clock running *behind* the server is accepted
  up to just under two windows (nearly 10 minutes) of apparent lag, while a
  client clock running *ahead* of the server has no tolerance at all — once it
  crosses into the next bucket, its token is rejected until the server follows.
  Comparison is `hmac.Equal` (constant time).
* Both sides must agree on `server_id`. The client defaults it to
  `endpoint.ID`; the server uses `ServerConfig.ServerID`.

### 4.2 Cookie encoding

`FormatCookie(token, format)`:

| Format | Cookie |
|---|---|
| `generic` (default, and any unrecognised value) | `sid=<token>` |
| `django` | `sessionid=<token>` |
| `wordpress` | `wordpress_logged_in_<hex8>=<token>` where `<hex8>` is the first 4 bytes of `SHA-256(token)` in lowercase hex |

The purpose is that the cookie looks like something the cover site's framework
would plausibly set. A raw hex MAC in a header would stand out immediately to
anyone who can read inside TLS.

`ParseCookie(part, format)` is the inverse:

* `generic` — requires the literal prefix `sid=`, returns the remainder;
* `django` — requires the prefix `sessionid=`, returns the remainder;
* `wordpress` — returns everything after the **last** `=` in the string,
  ignoring the name entirely. This is deliberately loose so that the random
  hash suffix does not have to be reproduced, but it means that under the
  `wordpress` format **any** cookie whose value happens to be a valid token is
  accepted, and the cookie name is not checked at all.

### 4.3 Server-side validation

`Server.authenticateClient`:

1. If the `Cookie` header is absent or empty → fail immediately. This
   short-circuit is not secret-dependent.
2. Split the header on `;`, trim each part, and `ParseCookie` it with the
   server's configured format. Parts that do not parse are skipped — also not
   secret-dependent.
3. For each parsed token, iterate over **every** entry of
   `ServerConfig.UserSecrets`, calling `ValidateAuthToken` on each, and record
   whether any matched. The loop MUST NOT return early on a match: total work
   is `O(len(UserSecrets) × HMAC)` regardless of whether and where a match
   occurs, which removes the timing oracle that would otherwise reveal which
   bucket matched when averaged over many probes.

The server does not learn *which* user matched, and does not use the identity
for anything: authentication is a boolean gate.

### 4.4 Failure behaviour

A `POST` to the configured API path that fails authentication is **not**
rejected and **not** passed to the file server. It is answered by `apiDecoy`
(§10.1) with the refusal the configured cover framework would produce, and a
constant JSON error body that is identical for a missing and a wrong token, so
nothing distinguishes "wrong token" from "no token". A GET on the same path
gets the same answer as a POST; any other method gets 405 with
`Allow: GET, POST`. Requests to any other path go to the cover site handler.

---

## 5. Key exchange and record protection

### 5.1 Frame order

Immediately after the POST returns 200:

```
client → server:  frame KEY_EXCHANGE, payload = client X25519 public key (32 bytes)
server → client:  frame KEY_EXCHANGE, payload = server X25519 public key (32 bytes)
```

Both sides then compute the ECDH shared secret. The client rejects a first
server frame whose type is not `KEY_EXCHANGE` or whose payload is not exactly
32 bytes; the server applies the same check to the client frame. Both keys are
ephemeral, generated per connection with `crypto/ecdh` X25519 and
`crypto/rand`, which is what provides forward secrecy for the tunnel payload
independently of the TLS session.

The key exchange frames are **not** encrypted by Chamele0nX (they are inside
TLS).

Each `KEY_EXCHANGE` frame is written together with a trailing padding frame (a
`PING` the peer reads and discards) in a single TLS record whose length is
randomised per write. The frame format is unchanged — a peer that does not pad
still interoperates by sending the bare frame — but the record is no longer a
fixed ~69 bytes at a fixed position at the very start of every session, which
would otherwise be a size-and-position constant a passive observer matches
without decrypting.

### 5.2 Key derivation

```
session_key = HKDF-SHA256(
                 secret = X25519_shared_secret,
                 salt   = nil,
                 info   = "chameleon-session-v1"
              ) [first 32 bytes]
```

`deriveSessionKey` reads exactly 32 bytes from the HKDF reader. Salt is `nil`
(HKDF-Extract therefore uses a zero salt of hash length). The info string is
the ASCII literal `chameleon-session-v1`, and it is the only version marker in
the protocol; there is no negotiation around it.

The shared secret is zeroized (`chcrypto.Zeroize`) as soon as the session key
is derived, on both sides.

**One key, both directions.** A single 32-byte key protects client → server and
server → client traffic. There is no directional key separation.

### 5.3 Record protection

Every `DATA` frame payload is:

```
+-----------------+---------------------------+---------------+
| nonce (12 B)    | ciphertext (len(pt) B)    | GCM tag (16 B)|
+-----------------+---------------------------+---------------+
```

* Cipher: **AES-256-GCM** (`crypto/aes` + `cipher.NewGCM`), key exactly
  32 bytes or `ErrInvalidKeySize`.
* Nonce: 12 bytes (`gcm.NonceSize()`), drawn from `crypto/rand` **per
  message**, prepended to the output by `gcm.Seal(nonce, nonce, pt, nil)`.
* No additional authenticated data.
* Overhead per `DATA` frame is therefore **28 bytes** on top of the plaintext,
  plus the 6-byte frame header.
* Decryption rejects inputs shorter than the nonce (`ErrCiphertextTooShort`)
  and any authentication failure (`ErrDecryptionFailed`, deliberately
  uninformative).

Nonces are random rather than counter-based. The birthday bound for random
96-bit nonces under one key is the operative limit on how much data a single
session should carry; the implementation does not enforce a rekey threshold
and does not count frames.

There is no sequence number and no replay window at this layer: an attacker who
can inject into the TLS stream is already assumed to have broken the outer
layer.

### 5.4 Zeroization

`chcrypto.Zeroize` overwrites a slice with zeros and calls `runtime.KeepAlive`
so the writes are not eliminated as dead stores. It is applied to:

* the decoded `user_secret`, deferred in `connect`;
* the X25519 shared secret, on both sides, immediately after derivation;
* the session key — on the client in `Tunnel.Close`, on the server
  deferred in `handleTunnel`.

This is best-effort: Go's garbage collector may have copied the value during
heap compaction, so zeroization removes the primary copy but cannot guarantee
no residue.

---

## 6. Frame layer

### 6.1 Layout

```
 0        1        2        3        4        5        6              6+N
 +--------+--------+--------+--------+--------+--------+--------------+
 |     type (2)    |            length (4)             |  payload (N) |
 +--------+--------+--------+--------+--------+--------+--------------+
   big-endian uint16          big-endian uint32          N = length
```

`frameHeaderSize` = 6 bytes.

### 6.2 Types

| Value | Name | Direction | Payload |
|---|---|---|---|
| `0x0001` | KEY_EXCHANGE | both, once each at start | X25519 public key, exactly 32 bytes |
| `0x0002` | DATA | both | AES-256-GCM envelope of one stream frame (§5.3, §7) |
| `0x0003` | PING | defined as keepalive | empty, or a timestamp |
| `0x0004` | CLOSE | client → server in practice | empty |

Unknown frame types are ignored by both peers: the server logs a warning and
continues, the client's `readLoop` falls through its switch and continues.
Receivers MUST tolerate unknown types this way; this is the only forward
extension point the framing provides.

### 6.3 Size limit

`maxFramePayload` = **65536 bytes** (64 KiB).

* `WriteFrame` refuses to write a larger payload and returns
  `ErrFrameTooLarge`; nothing is written.
* `ReadFrame` reads the 6-byte header, and if the declared length exceeds the
  limit returns `ErrFrameTooLarge` **before** allocating or consuming the
  payload. The connection is then desynchronised and the caller treats the
  error as fatal — both `readLoop` and `relayTunnel` return, which tears the
  tunnel down.

Senders stay well inside the limit by construction: relay buffers are 32 KiB
(TCP path) and 64 KiB (UDP read buffer), plus a 5-byte stream header and 28
bytes of AEAD overhead. A single 64 KiB UDP datagram plus overhead would
exceed the limit; in practice UDP payloads that large do not occur on the
paths this carries (DNS, QUIC).

### 6.4 Atomicity

`WriteFrame` serialises header and payload into one buffer and issues a
**single** `Write`. This matters because several goroutines may write frames on
one tunnel; a split write could interleave. Callers additionally hold a mutex
around the encrypt-and-write sequence (`writeFn` on both peers).

### 6.5 PING and CLOSE, as actually implemented

* Neither peer ever **sends** PING. The client ignores received PINGs.
* The server's PING branch attempts to reply by writing to the request body
  reader via a type assertion `reader.(io.Writer)`. The request body is not an
  `io.Writer`, so this assertion would panic if a peer ever sent a PING frame.
  This path is unreachable from the reference client, but it is a live defect
  rather than a working keepalive: an implementer writing a third-party client
  MUST NOT send PING to this server.
* CLOSE is sent by the client from `Tunnel.Close`. The server treats
  it as end of session and returns from `relayTunnel`. The server never sends
  CLOSE; it signals shutdown by ending the HTTP response.
* If the server receives a **KEY_EXCHANGE** frame in the middle of a relay
  session it treats it as a reset signal and returns from `relayTunnel`, so the
  session is recycled rather than left half-dead while the client waits for a
  reply it will never get.

---

## 7. Stream layer (multiplexing)

One HTTP/2 POST carries many logical streams. Stream frames are the plaintext
inside `DATA` frames.

### 7.1 Layout

```
 0        1        2        3        4              4+N
 +--------+--------+--------+--------+--------+------------+
 |          stream_id (4)            | type(1)|  data (N)  |
 +--------+--------+--------+--------+--------+------------+
   big-endian uint32                   uint8
```

`streamHeaderSize` = 5 bytes. `DecodeStreamFrame` rejects anything shorter
than 5 bytes.

### 7.2 Stream types

| Value | Name | Direction | Data |
|---|---|---|---|
| `0x01` | CONNECT | client → server | `[host_len:1][host:N][port:2]` |
| `0x02` | DATA | both | raw TCP payload fragment |
| `0x03` | FIN | both | empty — stream closed, no more data |
| `0x04` | RST | both | empty — stream reset (error) |
| `0x05` | CONNECT_UDP | client → server | same encoding as CONNECT |
| `0x06` | DATAGRAM | both | exactly one UDP datagram |

Values outside this set are logged and dropped by the server; on the client an
unknown type reaching a stream is ignored by `Stream.deliver`.

### 7.3 CONNECT payload

```
 0        1                    1+H            3+H
 +--------+--------------------+--------------+
 |host_len|      host (H)      |   port (2)   |
 +--------+--------------------+--------------+
   uint8      ASCII, H ≤ 255     big-endian
```

`DecodeConnect` rejects payloads shorter than 4 bytes and payloads truncated
relative to the declared `host_len`. The host is an IPv4 literal in dotted form
or a domain name; IPv6 literals never reach this encoding because the client's
SOCKS5 front end rejects `ATYP = 0x04` first (§8.5).

### 7.4 Stream identifiers

* IDs are allocated by the **client only**, from a monotonic counter
  (`Mux.nextID.Add(1)`), so the first stream on a tunnel is `1`. There are no
  parity or range rules: the server never originates a stream, so no collision
  is possible.
* The server registers the ID the client chose (`Mux.AcceptStream`) when it
  sees CONNECT or CONNECT_UDP. Registration happens **before** the dial
  goroutine starts, so DATA or DATAGRAM frames that arrive while the outbound
  socket is still being established are buffered into the stream rather than
  dropped.
* IDs are unique within one tunnel and are not reused after close. The counter
  is 32-bit and wraps after 2³² streams; no session is expected to live that
  long, and the code does not check for wrap.
* Frames naming an unknown stream ID are silently discarded by the dispatch
  loop.

### 7.5 Lifecycle and closure

* `OpenStream` / `OpenStreamUDP` register the stream locally, then send
  CONNECT / CONNECT_UDP. If that write fails the stream is unregistered and the
  error is returned. There is no acknowledgement frame: the client's SOCKS5
  front end replies success to the application as soon as the CONNECT frame has
  been written, before the server has dialled. A dial failure surfaces later as
  a FIN, not as a SOCKS5 error code.
* `Stream.Close` sends **FIN** once (guarded by an atomic swap), closes local
  state, and deletes the stream from the mux.
* Receiving **FIN or RST** closes the local stream; buffered reads then return
  `io.EOF`. The reference implementation never *sends* RST — it is accepted but
  not generated.
* `Mux.Close` closes every registered stream without sending FIN for each, and
  stops the dispatch loop. Tunnel teardown therefore relies on the transport
  closing, not on per-stream frames.
* Buffering: the mux dispatch queue holds 256 frames; each stream holds 64
  chunks. These are backpressure limits, not advertised flow control — there is
  **no** per-stream flow-control window in Chamele0nX; the only windowing is
  HTTP/2's, which applies to the whole tunnel.

### 7.6 Byte streams versus datagrams

A stream is used in one mode or the other, never both:

* `Stream.Write` / `Stream.Read` implement a byte stream (type `DATA`).
  `Read` preserves leftover bytes in an internal buffer, so frame boundaries
  are **not** visible to the reader.
* `Stream.WriteDatagram` / `Stream.ReadDatagram` implement message semantics
  (type `DATAGRAM`): exactly one frame per call in each direction, so datagram
  boundaries survive end to end.

---

## 8. UDP over the tunnel

### 8.1 Client side: SOCKS5 UDP ASSOCIATE

On a SOCKS5 request with `CMD = 0x03` the client (`handleUDPAssociate`,
`udp_client.go`):

1. binds a UDP relay socket on `127.0.0.1:0`;
2. replies `05 00 00 01 7F 00 00 01 <port:2>` — success, ATYP IPv4,
   BND.ADDR `127.0.0.1`, BND.PORT = the bound port;
3. clears the deadline on the control TCP connection and keeps it open; the
   lifetime of that connection **is** the lifetime of the association;
4. relays datagrams until either the control connection closes or the relay
   socket fails, then tears down the relay socket and every flow stream.

If the relay socket cannot be bound, the client replies `05 01 …` (general
SOCKS server failure).

### 8.2 Datagram format on the loopback socket

Standard RFC 1928 §7:

```
 +-----+-----+------+----------+----------+----------+
 | RSV | RSV | FRAG |   ATYP   | DST.ADDR | DST.PORT |  DATA
 +-----+-----+------+----------+----------+----------+
 |  1  |  1  |  1   |    1     | variable |    2     |  variable
```

`parseUDPHeader` returns the destination, the raw `ATYP‖ADDR‖PORT` slice, and
the payload. `buildUDPDatagram` rebuilds a reply header by prefixing
`00 00 00` to the stored raw address slice — replies therefore always carry the
address form the client originally used.

### 8.3 Carriage over the tunnel

Only the **payload** crosses the tunnel. The SOCKS5 UDP header is stripped on
the way in and rebuilt on the way out; the destination is carried once, in the
CONNECT_UDP payload, when the flow is opened. Each datagram is exactly one
`DATAGRAM` stream frame in exactly one `DATA` tunnel frame, so boundaries are
preserved end to end. No new port is opened and no plaintext UDP appears on the
wire.

### 8.4 Flow table

A **flow** is keyed by the pair (client source address, destination):

```
key = "<src_ip>:<src_port>|<dst_host>:<dst_port>"
```

| Property | Value |
|---|---|
| Key | source address ‖ `|` ‖ destination host:port |
| First datagram | opens a mux stream via `OpenStreamUDP` |
| Reader | one goroutine per flow, `ReadDatagram` → rebuild header → `WriteToUDP` to the stored client address |
| Max flows | `maxUDPFlows` = **256** per association |
| Over the limit | the datagram is dropped silently; no error to the application |
| Write failure | the flow is evicted and the stream closed, so a later datagram re-opens it |
| Relay read buffer | `udpRelayBufSize` = 65536 bytes |

### 8.5 ATYP handling

| ATYP | Client SOCKS5 CONNECT (§3, TCP) | Client UDP relay |
|---|---|---|
| `0x01` IPv4 | accepted | accepted |
| `0x03` domain | accepted | accepted |
| `0x04` IPv6 | rejected with SOCKS5 reply `0x08` (address type not supported) | datagram dropped (`errUDPIPv6Blocked`) |
| other | rejected with `0x08` | datagram dropped (`errUDPBadATYP`) |

`FRAG != 0` is rejected (`errUDPFragUnsupported`) — Chamele0nX never fragments.
Short or truncated headers are dropped (`errUDPShortHeader`,
`errUDPTruncated`). All of these are drops, not errors returned to the
application: a malformed or unsupported datagram simply disappears.

IPv6 is blocked rather than passed through because the tunnel carries IPv4
only; letting an IPv6 destination through would send that flow outside the
tunnel.

### 8.6 Server side

`handleStreamConnectUDP`:

1. applies the same SSRF gate as TCP (literal private/loopback/link-local
   addresses rejected before the dial; the post-dial peer address re-checked to
   catch DNS rebinding);
2. dials `udp` to the destination;
3. relays in both directions, one `Write` per datagram;
4. resets the read deadline to `defaultUDPIdleTimeout` = **45 s** before every
   read, so a flow with no inbound traffic tears down. This is deliberately far
   shorter than the 5-minute TCP idle timeout, because UDP has no FIN and DNS
   and QUIC flows are short-lived.

Blocked private ranges (`isPrivateIP`): `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`,
`fe80::/10`. `ServerConfig.AllowPrivateTargets` disables the gate and is for
tests only.

Note that `Transport.Info()` reports `SupportsUDP: false` even though the UDP
path described here is implemented; the field has not been updated.

---

## 9. Traffic shaping

Shaping controls two observables: **TLS record sizes** and **inter-burst
timing**. It is applied by `ShapedConn`, which wraps the TLS connection beneath
the HTTP/2 framer, on both peers.

### 9.1 SiteProfile JSON schema

```json
{
  "name": "saas-dashboard-default",
  "version": 1,
  "record_size_distribution": [
    {"min_size": 64,    "max_size": 200,   "weight": 0.15},
    {"min_size": 200,   "max_size": 800,   "weight": 0.25},
    {"min_size": 10000, "max_size": 16384, "weight": 0.05}
  ],
  "burst_pattern": {
    "records_per_burst":  {"min": 5, "max": 15},
    "burst_duration":     {"min_ms": 500, "max_ms": 2000},
    "inter_burst_pause":  {"min_ms": 50,  "max_ms": 250},
    "inter_record_delay": {"min_ms": 0,   "max_ms": 50}
  },
  "session_profile": {
    "duration":                {"min_ms": 180000, "max_ms": 900000},
    "bursts_per_session":      {"min": 5, "max": 30},
    "total_bytes_per_session": {"min": 500000, "max": 10000000}
  },
  "upload_download_ratio": 0.1,
  "concurrent_streams": {"min": 1, "max": 6},
  "bypass_pause_cap": false
}
```

| Field | Type | Unit | Meaning | Constraint (`Validate`) |
|---|---|---|---|---|
| `name` | string | — | human-readable identifier | none |
| `version` | int | — | profile format version | MUST equal `1` |
| `record_size_distribution` | array of bucket | — | histogram of TLS record payload sizes | MUST be non-empty |
| `…[].min_size` | int | bytes | bucket lower bound | ≥ 64 (`minTLSRecord`), ≤ `max_size` |
| `…[].max_size` | int | bytes | bucket upper bound | ≤ 16384 (`maxTLSRecord`) |
| `…[].weight` | float | probability | relative selection weight | ≥ 0; all weights MUST sum to 1.0 ± 0.01 |
| `burst_pattern.records_per_burst` | {min,max} int | records | how many records before a pause | `min` MUST be > 0 |
| `burst_pattern.burst_duration` | {min_ms,max_ms} | ms | intended wall-clock span of a burst | unvalidated; **not used by `ShapedConn`** |
| `burst_pattern.inter_burst_pause` | {min_ms,max_ms} | ms | pause sampled after each burst | unvalidated |
| `burst_pattern.inter_record_delay` | {min_ms,max_ms} | ms | delay between records inside a burst | unvalidated; used only by burst generation, **not by `ShapedConn`** |
| `session_profile.duration` | {min_ms,max_ms} | ms | intended session length | descriptive only |
| `session_profile.bursts_per_session` | {min,max} int | bursts | intended bursts per session | descriptive only |
| `session_profile.total_bytes_per_session` | {min,max} int | bytes | intended volume per session | descriptive only |
| `upload_download_ratio` | float | ratio | upload ÷ download of the modelled site | MUST be in (0, 1] |
| `concurrent_streams` | {min,max} int | streams | typical concurrent HTTP/2 streams | descriptive only |
| `bypass_pause_cap` | bool | — | opt out of the 250 ms inline pause cap | default false |

The fields marked *descriptive only* are carried, validated where noted, and
consulted by tooling and by humans reading a profile, but no code path in the
shaper reads them. An implementer MUST NOT assume that setting
`session_profile` changes anything on the wire.

### 9.2 Profile resolution

In `Transport.connect`, in this order:

1. `chameleon_profile` empty → `DefaultSaaSProfile()`;
2. else if it names a built-in (`BuiltInProfileByName`) → that struct;
3. else treat it as a filesystem path → `LoadProfile`, which reads, unmarshals
   and validates, failing the connect on error.

Built-in names (case-insensitive, trimmed):

| Name and aliases | Profile |
|---|---|
| `balanced`, `saas`, `saas-dashboard`, `default` | `DefaultSaaSProfile` |
| `stealth`, `stealth-admin`, `admin-console` | `DefaultStealthProfile` |
| `aggressive`, `bulk`, `performance` | `DefaultAggressiveProfile` |
| `wordpress`, `wp`, `wp-admin` | `DefaultWordPressProfile` |
| `lowpower`, `low-power`, `mobile`, `embedded` | `DefaultLowPowerProfile` |
| `server-downstream`, `server`, `downstream`, `fast-server` | `DefaultServerDownstreamProfile` |
| `saas-stealth`, `saas_stealth` | `DefaultSaaSStealthProfile` |
| `saas-fast`, `saas_fast` | `DefaultSaaSFastProfile` |
| `saas-max`, `saas_max` | `DefaultSaaSMaxProfile` |

The resolved profile is cached on the `Transport` and reused for subsequent
connects.

### 9.3 Per-client personalization

`PersonalizeFor(clientSeed)` returns a deep copy with deterministic jitter, so
that two clients running the same nominal preset do not share an identical
envelope and become mutually correlatable:

| Axis | Jitter | Notes |
|---|---|---|
| `weight` of each bucket | ±20 % | floored at 0.001, then all weights re-normalised to sum to 1.0 |
| `records_per_burst.min` / `.max` | ±30 %, independent per end | floor 1; `max` raised to `min` if it would fall below |
| `inter_burst_pause.min` / `.max` | ±50 %, independent per end | floor 0 |

Everything else — bucket bounds, `burst_duration`, `inter_record_delay`,
`session_profile`, `upload_download_ratio`, `concurrent_streams`,
`bypass_pause_cap`, `version` — is copied unchanged; those describe the profile
*type*, not its per-client expression. The copy's `name` gets a `-personal`
suffix. A seed of **0** returns the profile unchanged, which is what makes
seeded tests reproducible.

Jitter is derived by splitmix64 mixing of the seed with a slot index
(`mixSeed`), so it is stable within a connection and divergent between
connections.

### 9.4 Write path

`ShapedConn.Write(p)`:

1. If the profile is `nil`, write straight through, unshaped and unlocked.
2. Take the write mutex.
3. If `len(p) < minShapingThreshold` (**512 bytes**) write through unshaped and
   return. These are HTTP/2 control frames — SETTINGS, WINDOW_UPDATE, PING,
   most HEADERS — which should appear at their natural sizes. Such writes do
   **not** advance the burst counter.
4. Otherwise loop until `p` is consumed:
   a. `maybeBurstPause()` — possibly sleep (below);
   b. `nextRecordSize()` — sample a target size;
   c. write `min(target, remaining)` bytes to the inner connection as one
      `Write`, which with `DynamicRecordSizingDisabled` produces exactly one
      TLS record;
   d. increment the in-burst record counter and stamp the write time.

Note the consequence of step (c): the final chunk of a write is whatever is
left, so it may be smaller than the sampled target. `ShapedConn` never pads;
nothing on the live write path inserts padding bytes at all (§9.7).

### 9.5 Record size selection

`nextRecordSize`:

1. `sampleRecordSize()` picks a bucket by weighted selection over a
   `crypto/rand` draw, then a uniform size inside `[min_size, max_size]` of
   that bucket. If the cumulative weights fall short of the draw the last
   bucket is used.
2. A per-record seed is derived as `clientSeed XOR (counter × 0x9E3779B97F4A7C15)`
   with a monotonic counter, so consecutive records do not repeat a pattern.
3. `RandomizeSize(size, derivedSeed, 25)` applies **±25 %** deterministic
   jitter and clamps the result to `[64, 16384]`.
4. On a sampling error the fallback size is 4096 bytes.

On the wire, a record with an N-byte payload costs N + 5 bytes of TLS record
header + 17 bytes of TLS 1.3 AEAD overhead (1 inner content type + 16 tag).

### 9.6 Burst timing

`maybeBurstPause`, called before each shaped record and holding the write
mutex:

1. No burst target yet (first ever write) → pick one, do not sleep.
2. `recordsInBurst < burstTarget` → return, do not sleep.
3. Burst complete → sample a pause, subtract time already elapsed since the
   last write (**natural-gap deduction**), sleep for the remainder if positive,
   reset the counter and pick a new target.

| Element | Rule |
|---|---|
| Burst target | `cryptoRandRange(records_per_burst.min, .max)`; falls back to `defaultBurstTarget` = 10 on error or a non-positive result |
| Pause sample | `cryptoRandDuration(inter_burst_pause.min, .max)`; 0 if `max ≤ 0` |
| Pause cap | clamped to `maxBurstPauseInWrite` = **250 ms** unless `bypass_pause_cap` is true |
| Natural gap | if the connection was already idle longer than the sampled pause, no sleep at all |

The cap exists because the sleep happens inline, under the write mutex, and
therefore blocks **every** HTTP/2 stream on the connection for its duration. A
30-second pause from a naively-authored profile would stall all interactive
traffic. Profiles for which long pauses are the point (Stealth) opt out with
`bypass_pause_cap`.

Natural-gap deduction is what keeps the shaper invisible on chat and
tab-switching traffic: the timing cost has already been paid by the
application's own idleness, so nothing extra is imposed. It only bites when an
application is actually streaming bulk data.

### 9.7 What is *not* on the shaping path

`SiteProfile.GenerateBurst` samples a whole burst from a profile at once: an
explicit list of record sizes, an `InterRecordDelay` between them and a
`PostBurstPause` after them. Its only consumer is `cmd/chamele0nx-validator`,
which synthesises traffic offline to test a profile against itself. The live
client and server data path never calls it; that path goes through
`ShapedConn`. An earlier revision also shipped writers that emitted such a
burst onto a connection, padding short records with random bytes to hit their
target size. Nothing but their own tests used them and they have been removed,
so no part of this repository pads a record. Read `GenerateBurst` as a
description of a profile's intent, not of what a Chamele0nX peer emits.

What a peer emits is described instead by `SiteProfile.EmittedSizePMF`: the
bucket histogram with the ±`RecordJitterPercent` per-record jitter folded in
and the result clamped to a legal record payload. That is the distribution the
validator tests against, because it is the one an observer measures. The two
differ most where a bucket reaches the 16 KB ceiling, since the upward jitter
that would cross it is clamped back onto it and leaves an atom there.

### 9.8 Direction

Shaping is applied independently on each side:

* **Upstream (client → server).** Always on. `ShapedConn` wraps the dialed TLS
  connection with the personalized profile.
* **Downstream (server → client).** On by default, but *armed only after
  authentication*. The wrapper starts un-armed: until a tunnel POST
  authenticates, every server write goes out unshaped, so an unauthenticated
  probe — the cover site or an `apiDecoy` answer — never sees the shaping
  envelope. Shaping switches on the moment the client authenticates
  (`armShaping`/`ShapedConn.Arm`). Each accepted connection gets its own seed,
  and the server's profile is personalized per connection before wrapping. The
  server default profile is
  `DefaultServerDownstreamProfile` (not the SaaS profile), which uses 15–30
  records per burst, 20–80 ms pauses, and a size distribution biased toward
  5–16 KB — matching how a real backend flushes a batched response. An operator
  who sets `ServerConfig.Profile` explicitly gets exactly that instead.
* **Kill switch.** `ServerConfig.DisableDownstreamShaping` skips the wrapper
  entirely and serves the raw TLS connection. This is a strictly weaker
  configuration: downstream traffic becomes a continuous stream again, which is
  visible to a classifier watching long sessions. It exists because symmetric
  shaping with the client profile was measured to cut throughput several-fold
  on a real link, and an operator needs an escape hatch that does not require a
  rebuild.

Asymmetry is intentional and realistic: a real SaaS client sends small POSTs
and receives bulky batched responses.

---

## 10. Cover behaviour

### 10.1 Unauthenticated requests

| Request | Response |
|---|---|
| `GET` or `POST` to the configured API path without valid auth | `apiDecoy`: the refusal belonging to `cookie_format` (see below), `Content-Type: application/json`, random `X-Request-Id`, and a constant body |
| Any other method on that path | `apiDecoy`: HTTP 405 with `Allow: GET, POST` and a constant JSON error body |
| Anything else | the cover site handler |

`apiDecoy` exists because falling through to a file server would emit Go's plain
404 for an API path — a real `/api/v1/events` always answers JSON, so the
mismatch is a clean discriminator for an active prober. It answers uniformly, the
way a real cookie-protected endpoint does: a `GET` or `POST` without valid
credentials is refused, identically on both methods; any other method returns
405 with an `Allow` header naming the methods the endpoint implements.

The refusal follows `cookie_format`, because the session cookie has already
committed the cover site to a framework and the two must belong to the same
application:

| `cookie_format` | Status | Body | `Content-Type` |
|---|---|---|---|
| `generic` (default) | 401 | `{"error":"unauthorized",…}` | `application/json` |
| `wordpress` | 401 | `{"code":"rest_not_logged_in",…}` | `application/json; charset=UTF-8` |
| `django` | **403** | `{"detail":"Authentication credentials were not provided."}` | `application/json` |

Django is 403 rather than 401 on purpose: DRF's session authentication
declares no auth scheme, so it has nothing to name and downgrades the status
instead.

None of them sends `WWW-Authenticate`. RFC 9110 §15.5.2 says a 401 should
carry one; the software being imitated does not — verified against live
WordPress installations, which answer an unauthenticated REST request with
401, `application/json; charset=UTF-8`, and no such header. Imitation wins
over specification compliance here, because a header the real thing omits is
a new discriminator, not a fix.

The bodies are deliberately constant — a real API's error bodies are constant
too, so a fixed length here is faithful, not a tell. The `X-Request-Id` header
still varies per call, as a real request-tracing middleware emits it.

### 10.2 The cover site

| `CoverSiteDir` | Behaviour |
|---|---|
| set | `http.FileServer` over that directory — a real static site |
| empty | `defaultCoverHandler`, a minimal JSON API: `/api/v1/health` → `{"status":"ok","version":"2.1.0","uptime":…}`; `/api/v1/events` → `{"events":[],"cursor":"","has_more":false}`; anything else → 404 with a JSON error body. Every response carries a random `X-Request-Id` (random, not a sequential timestamp, which would itself be a discriminator) |

The built-in handler is a fallback for testing and small deployments. Every
response is a fixed-length body carrying a random `X-Request-Id`, the same shape
`apiDecoy` now returns — `apiDecoy` covers the configured API path, answering it
as a protected endpoint, while this handler covers everything else.

### 10.3 Cover profiles (registry)

`CoverProfile` (`cover.go`) is the abstraction for "which masquerade this
session wears": ID, description, and `Open` returning a duplex `net.Conn` that
the common mux/crypto/auth stack layers onto. Profiles are stateless singletons
registered at `init()` into a process-global registry;
`endpoint.Params["cover"]` selects one, defaulting to `DefaultCoverID` =
`saas-http2`, and an unregistered ID is rejected up front with a message
listing what the build does have.

**Honest status.** `saasHTTP2Cover.Open` is a stub that returns an error. The
real path — uTLS dial, `ShapedConn`, `imroc/req` HTTP/2, POST pipe, key exchange —
is still inline in `Transport.connect`. The registry today therefore does two
things and only two: it reserves the name so a client can be told whether this
build supports the mask it asked for, and it pins the log description. Selecting
a cover does not currently change any code path, because there is exactly one
registered cover and the connect path is hard-wired to it. An implementer
should read the abstraction as a planned seam, not as a working plug-in point.

### 10.4 Decoy traffic

`DecoyDriver` (`decoy.go`) is a **client-side** background loop that fetches
small resources from popular third-party endpoints, **outside** the tunnel. Its
purpose is the device's flow signature, not the tunnel's content: a device that
only ever opens one TLS connection to one IP looks nothing like a browser,
which fans out to CDNs, fonts, telemetry and package indices while a dashboard
is open.

| Parameter | Default |
|---|---|
| Interval between bursts | 30 s – 10 min, uniform (`crypto/rand`) |
| Fetches per burst | 3 – 6 |
| Gap within a burst | 200 ms – 3 s |
| Per-fetch timeout | 5 s |
| Bytes read then discarded | 4096 |
| Targets | supplied by the integrator. `ExampleDecoyTargets` holds 5 illustrative URLs (`cdn`, `fonts`, `dev-infra`, `reference`); the driver does **not** fall back to them |

Each fetch uses a fresh random User-Agent from the same pool (deliberately
*not* the connection's UA — decoy traffic should look like a normal device, not
like one identifiable Chamele0nX user), sets `Accept: */*`,
`Accept-Language: en-US,en;q=0.9`, and asks for the connection to be closed
after the response so TCP connections churn instead of being reused. It does
this with Go's `req.Close`, **not** a literal `Connection: close` header: that
header is illegal under HTTP/2 (RFC 7540 §8.1.2.2) and Go's h2 transport
rejects the request outright. Failures are counted and swallowed; a slow CDN
never affects the tunnel. Counters are exposed via `Metrics()`.

**Two honest caveats, both marked in the source:**

1. The driver is a no-op for stealth purposes unless the native VPN client
   excludes its sockets from the tunnel (`VpnService.protect` on Android,
   route exclusion on the iOS packet-tunnel provider). Without that, every
   decoy fetch is routed *through* the tunnel and simply adds requests to the
   one flow it was meant to disguise. It still runs and still reports metrics.
2. The default HTTP client is stdlib `crypto/tls`, whose TLS fingerprint
   differs from the tunnel's uTLS Chrome fingerprint. A production build SHOULD
   inject a uTLS-backed client so decoy and tunnel flows look like the same
   browser. The caveat is documented on `DecoyConfig.HTTPClient` in
   `decoy.go`.

---

## 11. Constants

| Constant | Value | Source |
|---|---|---|
| `tokenWindow` | 5 min (300 s) | `auth.go` |
| accepted token buckets | current and previous | `auth.go` |
| `minUserSecretBytes` | 16 | `chamele0nx.go` |
| pubkey pin length | 32 bytes (SHA-256 of DER SPKI) | `chamele0nx.go` |
| `frameHeaderSize` | 6 | `proto.go` |
| `maxFramePayload` | 65536 | `proto.go` |
| `frameKeyExchange` | `0x0001` | `proto.go` |
| `frameData` | `0x0002` | `proto.go` |
| `framePing` | `0x0003` | `proto.go` |
| `frameClose` | `0x0004` | `proto.go` |
| `streamHeaderSize` | 5 | `mux.go` |
| `streamConnect` | `0x01` | `mux.go` |
| `streamData` | `0x02` | `mux.go` |
| `streamFIN` | `0x03` | `mux.go` |
| `streamRST` | `0x04` | `mux.go` |
| `streamConnectUDP` | `0x05` | `mux.go` |
| `streamDatagram` | `0x06` | `mux.go` |
| mux dispatch queue | 256 frames | `mux.go` |
| `maxStreamBuffer` (per-stream receive queue) | 1 MiB, then that stream is reset | `mux.go` |
| `maxMuxBuffer` (all streams on one tunnel) | 32 MiB | `mux.go` |
| `maxConcurrentStreams` | 512 per tunnel, then `RST` | `mux.go` |
| `maxRequestHeaderKB` (HTTP/2 header limit) | 64 KiB | `server.go` |
| HKDF info string | `chameleon-session-v1` | `chamele0nx.go` |
| session key length | 32 bytes | `chamele0nx.go` / `chcrypto` |
| AEAD | AES-256-GCM | `chcrypto/encrypt.go` |
| GCM nonce | 12 bytes, random per message | `chcrypto/encrypt.go` |
| GCM tag | 16 bytes | `chcrypto/encrypt.go` |
| AEAD overhead per DATA frame | 28 bytes | derived |
| `maxTLSRecord` | 16384 | `shaper.go` |
| `minTLSRecord` | 64 | `shaper.go` |
| `tlsRecordHeader` | 5 | `shaper.go` |
| `tls13RecordOverhead` | 17 (1 + 16) | `shaper.go` |
| `minShapingThreshold` | 512 bytes | `shaped_conn.go` |
| `maxBurstPauseInWrite` | 250 ms | `shaped_conn.go` |
| `defaultBurstTarget` | 10 records | `shaped_conn.go` |
| per-record size jitter | ±25 % | `shaped_conn.go` |
| personalization jitter | weight ±20 %, records/burst ±30 %, pause ±50 % | `profile.go` |
| `SiteProfile.Version` | 1 (only accepted value) | `profile.go` |
| weight sum tolerance | 1.0 ± 0.01 | `profile.go` |
| `upload_download_ratio` bounds | (0, 1] | `profile.go` |
| `maxUDPFlows` | 256 per association | `udp_client.go` |
| `udpRelayBufSize` | 65536 | `udp_client.go` |
| `defaultUDPIdleTimeout` | 45 s | `server.go` |
| `defaultIdleTimeout` (TCP streams) | 5 min | `server.go` |
| TCP relay buffer | 32768 | `chamele0nx.go`, `persistent.go`, `server.go` |
| SOCKS5 handshake deadline | 30 s | `chamele0nx.go`, `persistent.go` |
| server dial timeout | 10 s | `server.go` |
| client TCP dial timeout | 15 s | `chamele0nx.go` |
| TLS session cache | LRU, 32 entries | `chamele0nx.go` |
| uTLS ClientHello | `HelloChrome_Auto` | `chamele0nx.go` |
| H2 `HEADER_TABLE_SIZE` | 65536 | `chamele0nx.go` |
| H2 `ENABLE_PUSH` | 0 | `chamele0nx.go` |
| H2 `INITIAL_WINDOW_SIZE` | 6291456 | `chamele0nx.go` |
| H2 `MAX_HEADER_LIST_SIZE` | 262144 | `chamele0nx.go` |
| H2 `ConnectionFlow` | 15663105 | `chamele0nx.go` |
| H2 pseudo-header order | `:method :authority :scheme :path` | `chamele0nx.go` |
| H2 header order | `cookie content-type accept user-agent` | `chamele0nx.go` |
| H2 read-idle / ping timeout (client) | 15 s / 5 s | `chamele0nx.go` |
| server H2 idle timeout | 120 s | `server.go` |
| server TLS handshake deadline | 15 s | `server.go` |
| default API path | `/api/v1/events` | `chamele0nx.go` |
| default cookie format | `generic` | `chamele0nx.go` |
| `DefaultCoverID` | `saas-http2` | `cover.go` |
| SNI pool size | 31 entries | `sni_pool.go` |
| User-Agent pool size | 5 entries | `useragent.go` |
| decoy targets | 5 examples, no default | `decoy.go` |
| decoy burst interval | 30 s – 10 min | `decoy.go` |
| decoy burst size | 3 – 6 fetches | `decoy.go` |
| decoy intra-burst gap | 200 ms – 3 s | `decoy.go` |
| decoy fetch timeout / byte cap | 5 s / 4096 | `decoy.go` |

---

## 12. Versioning and compatibility

### 12.1 There is no version negotiation

This is the single most important compatibility fact about Chamele0nX as
implemented. Nothing on the wire announces a protocol version:

* the first frame is a key exchange, not a hello;
* the HKDF info string `chameleon-session-v1` is a fixed constant compiled into
  both peers, never transmitted and never compared;
* `SiteProfile.Version` versions the *profile file format*, is checked only by
  the process that loads the file, and never crosses the wire;
* HTTP headers carry no version marker — adding one would be a fingerprint.

Practical consequences:

* A version mismatch between client and server does **not** produce a clean
  error. It produces a decryption failure, a frame-parse failure, or a hang,
  depending on where the divergence lands. Operators debugging a mismatched
  deployment will not get a message that says so.
* Both peers MUST be upgraded together for any change to the framing, the
  stream encoding, the key derivation, or the AEAD envelope.
* There is no way for a new client to detect an old server before committing to
  a session.

### 12.2 Breaking changes

Any of the following breaks compatibility with an unupgraded peer:

| Change | Why it breaks |
|---|---|
| Frame header layout or field widths | `ReadFrame` desynchronises |
| New frame type **that the sender requires a response to** | receivers ignore unknown types silently, so the sender hangs |
| Stream header layout, or reassigning a stream type value | `DecodeStreamFrame` mis-parses or dispatches wrongly |
| CONNECT payload encoding | `DecodeConnect` mis-parses the destination |
| HKDF info string, hash, or salt | both derive different keys; every DATA frame fails to decrypt |
| AEAD algorithm, key length, nonce length, or `nonce ‖ ct ‖ tag` layout | decryption fails |
| Token formula, window length, or the accepted-bucket set | authentication fails; the client sees the decoy response |
| Cookie name or encoding, without a matching `chameleon_cookie` on both sides | `ParseCookie` returns nothing; authentication fails |
| Raising `maxFramePayload` on the sender only | the receiver rejects and tears down |

### 12.3 Non-breaking changes

| Change | Why it is safe |
|---|---|
| New frame type that is purely informational | unknown types are ignored by both peers |
| Any change to shaping profiles, on either side independently | shaping is unilateral; nothing is negotiated and the peer parses whatever record sizes arrive |
| SNI pool, User-Agent pool, decoy target list | client-local choices |
| Cover site content, decoy body distribution | server-local |
| Idle timeouts, buffer sizes, reconnect policy | local resource policy |

### 12.4 What this means for an implementer

Treat the constants in §11 as a frozen contract, deploy client and server from
the same revision, and do not rely on the peer rejecting anything gracefully.
If in-band versioning is added later it will itself be a breaking change,
because there is no field today in which to put it.

---

## 13. Security considerations

The adversary model, the attacks this protocol is intended to resist, and — more
importantly — the ones it does not, are in
[THREAT-MODEL.md](THREAT-MODEL.md). Read that document before relying on
Chamele0nX. The points below are the ones that follow directly from the wire
format and belong here.

* **The cover TLS session is not what protects the payload.** Chamele0nX runs its
  own X25519 + HKDF + AES-256-GCM envelope inside TLS. TLS provides the
  masquerade; the envelope provides confidentiality and forward secrecy of the
  tunnelled traffic.
* **SNI substitution trades one guarantee for another.** In pinned substitution mode,
  certificate name verification is off; the only thing standing between the
  client and an interceptor is the SHA-256 public-key pin, compared in constant
  time. If the pin is wrong, stale, or supplied by an untrusted channel, the
  connection is interceptable. A pin is mandatory precisely so this trade is
  explicit.
* **Authentication is a boolean gate, not identity.** The server checks whether
  *some* configured secret matches; it does not record which one, and nothing
  downstream is per-user. Constant-time iteration over all secrets is required
  and implemented (§4.3).
* **One key, both directions, random nonces, no rekey.** There is no directional
  key separation, no sequence numbering, no replay window, and no rekey
  threshold. Session lifetime is bounded operationally, not cryptographically.
* **Failure is undistinguished by design.** Bad authentication returns the same
  constant 401 as no authentication — a real protected endpoint's answer, not a
  tell. This is deliberate anti-probing behaviour and it also means
  misconfiguration looks exactly like an attack from the client's side.
* **The server dials arbitrary destinations for authenticated clients.** SSRF
  protection rejects private, loopback and link-local addresses before and after
  the dial, on both the TCP and UDP paths.
  `ServerConfig.AllowPrivateTargets` disables that gate and MUST NOT be set in
  production.
* **Logging contract.** At level Info and above the server logs only operational
  metadata — no client addresses, no destination hostnames, no tokens, no
  cookie values. Destination host and port appear only at Debug level, for
  failed dials and blocked SSRF attempts. Any new log call must be checked
  against this rule: a hostile reader of production logs must not be able to
  derive who connected or where they went.
* **Zeroization is best-effort** (§5.4) and does not defend against an attacker
  who can read process memory or a core dump at an arbitrary moment.
* **Shaping is a statistical defence, not a guarantee.** It changes what a
  passive classifier sees at the record layer. It does nothing against an
  adversary who can compromise an endpoint, correlate volume and timing across
  the whole path, or block by address.
