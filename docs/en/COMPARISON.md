# How this compares

Chamele0nX is one point in a design space that a lot of people have worked
in for a long time, most of them longer and with more users than this
project. This document tries to place it honestly: what each approach
hides, what an observer still sees, and where each one breaks.

Nothing here is a ranking. The right tool depends on which censor you
face, whether you can run a server, and how much throughput you need. A
tool that is "detectable in principle" but has ten million users and a
decade of hardening may serve you far better than one that is elegant on
paper.

A note on evidence: claims below are sourced where a source exists.
Reports from user forums are labelled as such — they are the field's
early-warning system, and they are also frequently wrong about causes.

---

## The table

| Approach | How it hides | What the censor sees | Where it breaks |
|---|---|---|---|
| **WireGuard / OpenVPN**, unmodified | It does not. Both are honest protocols with published wire formats and no obfuscation. | A fixed-size UDP handshake with a constant type byte, or OpenVPN's characteristic framing. Identification is a byte match. | Everywhere that filters at all. OpenVPN has been fingerprinted at scale with high accuracy and low false positives ([Xue et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen)). Fast, simple, excellent at what it was designed for, which is not this. |
| **Shadowsocks 2022** (SIP022) | An AEAD stream with no handshake at all — the connection is high-entropy bytes from the first packet. | A flow with no recognisable protocol structure. That absence is the signal. | Detection of "fully encrypted" traffic by entropy heuristics, deployed in China since 2021 ([Wu et al., USENIX Security 2023](https://gfw.report/publications/usenixsecurity23/en/)), and earlier by active probing ([Alice et al., IMC 2020](https://dl.acm.org/doi/10.1145/3419394.3423644)). Very fast and very simple; the hiding is the weak part. |
| **VLESS + REALITY** (Xray) | The server completes a TLS handshake carrying a real, popular site's certificate parameters; unauthenticated clients are forwarded to that real site. No certificate of your own is needed. ([XTLS/REALITY](https://github.com/XTLS/REALITY)) | An apparently ordinary TLS 1.3 connection to a well-known domain, with a correct certificate chain. | It stops being about the handshake. Users report blocking driven by traffic volume per address rather than by any content signature ([Xray-core discussion #3269](https://github.com/XTLS/Xray-core/discussions/3269) — user reports, not a measurement study). The handshake is excellent; what happens after it is not shaped. |
| **Trojan** | A genuine TLS connection to a server with a real certificate, falling back to serving a real website for anything unauthenticated. | An ordinary TLS session to a domain with a valid certificate. | Blocked at scale in China from October 2022, alongside several TLS-based proxies, escalating from ports to whole addresses ([net4people/bbs #129](https://github.com/net4people/bbs/issues/129)). The concept is sound; the deployments were identified. |
| **NaiveProxy** | Uses Chromium's own network stack, so the traffic is produced by the same code a real Chrome produces it with — not an imitation of it. ([klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)) | A Chrome HTTPS/2 session, because that is what it is. | Nothing widely reported. It needs a real domain, a real certificate and a real web server, and the client carries a large Chromium dependency. Of everything in this table, this is the closest relative to Chamele0nX's premise, and it solves the fingerprint half more thoroughly than we do. |
| **obfs4** | Randomises the handshake and pads, so the flow carries no protocol structure to match on. ([spec](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/blob/HEAD/doc/obfs4-spec.txt)) | A high-entropy flow with no handshake — deliberately shapeless rather than disguised. | The same "fully encrypted traffic" heuristic that catches Shadowsocks ([Wu et al., 2023](https://gfw.report/publications/usenixsecurity23/en/)), and TCP-level side channels that confirm probe-resistant proxies ([Frolov et al., NDSS 2020](https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/)). Still shipped and widely used; the binary was renamed *lyrebird* in 2023 ([Tor Project](https://support.torproject.org/tbb/lyrebird/)). |
| **meek / domain fronting** | The TLS SNI names a large CDN's domain while the encrypted HTTP `Host` header routes to the real destination inside the CDN. ([Fifield et al., PETS 2015](https://petsymposium.org/2015/papers/03_Fifield.pdf)) | A TLS connection to a major cloud provider. Blocking it means blocking that provider. | The providers turned it off. Google and Amazon in 2018; Azure blocked new resources from November 2022 and all remaining ones from January 2024 ([Microsoft](https://learn.microsoft.com/en-us/answers/questions/1421101/take-action-to-stop-domain-fronting-on-your-applic); [net4people/bbs #67](https://github.com/net4people/bbs/issues/67)). A brilliant technique that depended on someone else's configuration. |
| **Snowflake** | Ephemeral WebRTC connections through thousands of volunteer browser proxies, brokered on demand. ([Bocovich et al., USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich)) | A WebRTC session to an ordinary, constantly changing address. There is no fixed server to block. | The rendezvous step still needs a censorship-resistant channel, and WebRTC is itself identifiable where a censor is willing to block it broadly. Requires no server of your own, which is a property nothing else here has. |
| **Hysteria 2** | Rides on QUIC, so it looks like HTTP/3, with optional packet obfuscation. Its real selling point is throughput, not concealment. ([docs](https://v2.hysteria.network/)) | A QUIC flow with a visible SNI in the Initial packet. | SNI-based QUIC blocking, which China has performed at scale by decrypting Initial packets since 2024 ([Wu et al., USENIX Security 2025](https://gfw.report/publications/usenixsecurity25/en/)). Also: networks that throttle or drop UDP outright. |
| **Cloak** | Wraps another proxy in a TLS session to a decoy site, authenticating legitimate users steganographically in the `ClientHello` and forwarding everyone else to the decoy. ([cbeuw/Cloak](https://github.com/cbeuw/Cloak)) | An ordinary TLS session to the decoy domain. | Predates and closely resembles the REALITY idea, with the same limit: the handshake is disguised, the data stream that follows is not. We did not verify its current maintenance activity. |
| **AmneziaWG** | A WireGuard fork that removes WireGuard's fixed header signatures and, in later versions, shapes packets to resemble other protocols. ([docs](https://docs.amnezia.org/documentation/amnezia-wg/)) | UDP with randomised-looking headers, or packets shaped like another protocol's opening. | Reported as detected in Russia, with the project's own release notes describing a move by censors past per-packet signatures ([amnezia-client #1010](https://github.com/amnezia-vpn/amnezia-client/issues/1010)). Keeps WireGuard's speed and simplicity, which matters. |
| **Chamele0nX** | Carries traffic inside HTTP/2 requests to a real HTTPS site the operator runs, and reshapes TLS record sizes and burst timing to match a profile measured from real site traffic. | An ordinary HTTPS session to an ordinary site, whose record-size and timing statistics resemble that site rather than a tunnel. | The server's address, like everything else in this table that needs a server. One profile per server, so users of a server resemble each other. No independent evaluation. See [THREAT-MODEL.md](THREAT-MODEL.md). |

---

## What Chamele0nX does differently

One thing, and it is worth being precise about how small it is.

**The metadata is shaped to a measured profile.** Every other TLS-based
approach in the table hides the handshake and then lets the data stream
run at its natural shape: large records, back to back, for as long as the
application sends. Chamele0nX samples each record's size from a histogram
captured from real site traffic, groups records into bursts, and paces
the bursts. The server does the same in the downstream direction. The
claim is not that the payload is hidden — TLS already does that — but
that the *envelope* resembles the cover rather than a tunnel.

Everything else in the design is prior art, and mostly not ours:

* **Serving a real site to unauthenticated visitors** is the HTTPT idea
  ([Frolov and Wustrow, FOCI 2020](https://www.usenix.org/conference/foci20/presentation/frolov)),
  independently arrived at by Trojan, Cloak, NaiveProxy and REALITY.
* **Browser-accurate TLS fingerprints** come from uTLS
  ([Frolov and Wustrow, NDSS 2019](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03B-2-1_Frolov_paper.pdf)),
  which we use as a library.
* **Matching the HTTP/2 fingerprint** is standard practice in the
  anti-detection tooling world.
* **Rotating, unguessable authentication that leaves no artefact in the
  clear** is what every probe-resistant proxy does.
* **Traffic shaping as a defence** is a well-studied research area with
  better-evaluated designs than ours — see
  [RESEARCH.md](RESEARCH.md).

If you already run NaiveProxy or REALITY and they work on your network,
the honest advice is to keep running them. Chamele0nX is worth trying when
what is failing is not the handshake.

---

## What other projects do better

**Hysteria 2 is faster on bad links.** Its Brutal congestion control
targets a configured rate and does not back off on loss the way CUBIC or
BBR do, which is exactly the right behaviour on a lossy or deliberately
throttled path. The performance claims are the project's own rather than
independently benchmarked, but the mechanism is real and the direction is
correct. Chamele0nX runs over TCP and inherits every one of TCP's problems
on such links, and its shaper deliberately adds pauses on top.

**Xray is far more mature.** Years of deployment, a very large user base,
many client implementations, active development, and a community that
notices blocking within hours. Its handshake concealment is better
engineered than ours. Neither project has a published independent
security audit, as far as we could establish, but Xray has had orders of
magnitude more eyes on it.

**NaiveProxy solves the fingerprint problem more thoroughly.** By using
Chromium's actual network stack, it does not imitate a browser's TLS and
HTTP/2 behaviour — it executes it. Our uTLS-plus-tuned-HTTP/2 approach is
an approximation that has to be maintained as Chrome moves, and one that
ages silently.

**Snowflake needs no server.** For a user with no money, no technical
skills and no trustworthy contact abroad, that is not a detail — it is
the whole thing. Chamele0nX requires a domain, a certificate, a host and
someone to run them.

**WireGuard is simpler and faster than any of this.** A small, auditable
codebase, in-kernel performance, and a clear security argument. If your
network does not block it, use it.

**obfs4, meek and Snowflake have real deployment discipline.** Bridge
distribution, reproducible builds, measurement infrastructure, and a team
that has been doing this since 2013. This repository has none of that
apparatus.

**Client ecosystems.** Xray, Shadowsocks and WireGuard are supported by
sing-box, v2rayN, Nekoray, Amnezia and a dozen mobile clients. Chamele0nX
has a command-line client and a Go binding. See
[CLIENTS.md](CLIENTS.md).

---

## Lessons from mimicry protocols

There is a specific historical failure this design is trying to avoid,
and it is worth stating plainly because the design could still fall into
it.

In 2013, Houmansadr, Brubaker and Shmatikov examined systems that
achieved "unobservability by imitation" — a circumvention tool
implementing enough of Skype, or of an HTTP client, to pass for it — and
showed the approach fails structurally
([The Parrot is Dead, IEEE S&P 2013](https://www.ieee-security.org/TC/SP2013/papers/4977a065.pdf)).
The argument: a protocol has enormous surface. The imitation reproduces
the parts its author thought about, and an observer only has to notice
one part the author did not — an error the real client would return, a
control message the real protocol sends unprompted, a timer, a version
negotiation, a side channel. The imitator must be perfect everywhere. The
observer needs one discrepancy. Two years later, Wang, Dyer and
colleagues demonstrated exactly that against obfuscation systems in
deployment ([CCS 2015](https://dl.acm.org/doi/10.1145/2810103.2813715)).

The response the field converged on is not "imitate better" but "do not
imitate at all". Run the real protocol, with a real implementation, to a
real server, and hide inside it. HTTPT, NaiveProxy, Trojan, Cloak and
REALITY are all versions of this move. Chamele0nX is another: the TLS
handshake is a real TLS handshake, the certificate is a real certificate
for a domain the operator controls, the HTTP/2 is a real HTTP/2 session,
and the website an unauthenticated visitor gets is a real website that is
genuinely being served. There is no partial reimplementation for an
observer to catch out.

**But the shaping layer is an imitation, and it is fair to hold it to the
same standard.** It reproduces a measured distribution of record sizes
and burst timings. It does not reproduce everything a real site's traffic
does: not the long idle gaps, which are clamped for latency reasons; not
the exact fan-out of a page load across many hosts; not the correlation
between what a user clicks and what the network then does. A classifier
built specifically against this shaper, with access to this repository
and to the cover site's real traffic, is not obviously defeated by it.
The parrot argument applies to distributions too, and we have not
measured how far it applies here.

What the design does claim is narrower and, we think, defensible: it
raises the cost of bulk classification, because the cheap features that
separate tunnels from browsing no longer separate them. It does not
claim to survive a classifier built for it specifically.

---

## See also

* [THREAT-MODEL.md](THREAT-MODEL.md) — what this defends against, and
  the longer list of what it does not.
* [RESEARCH.md](RESEARCH.md) — the papers behind all of the above.
* [FAQ.md](FAQ.md) — shorter answers to most of these questions.
