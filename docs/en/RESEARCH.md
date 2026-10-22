# Research this design draws on

An annotated reading list. Every entry is here because it shaped a
decision in this repository, or because it describes an attack this
design has to survive. Each item says, in one line, what it means for
Chamele0nX specifically.

Only sources whose existence was checked are listed. Where a claim
circulating in the community has no verifiable source behind it, it is
not cited here.

---

## 1. Classification of encrypted traffic

The premise of the whole design is that an observer who cannot read your
traffic can still classify it from its shape. This is the literature that
establishes that.

**Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis
Countermeasures Fail** — Dyer, Coull, Ristenpart, Shrimpton. IEEE S&P
2012. <https://dl.acm.org/doi/10.1109/SP.2012.28>
Nine general-purpose countermeasures, most of them based on padding
packet lengths, fail against classifiers using coarse features such as
total volume and timing. *For us:* per-record padding alone is not a
defence. It is why the shaper works on distributions and burst structure
rather than on individual record sizes.

**Rosetta: Enabling Robust TLS Encrypted Traffic Classification in
Diverse Network Environments with TCP-Aware Traffic Augmentation** — Xie,
Cao, Dong, Xu, Sun, Li, Shen, Zhang. USENIX Security 2023.
<https://www.usenix.org/conference/usenixsecurity23/presentation/xie>
Classifies TLS traffic from packet-length sequences, and stays accurate
when network conditions change. *For us:* the direct statement of the
threat the shaper exists to address, and evidence that a classifier does
not need a stable network to work.

**Website Fingerprinting at Internet Scale** — Panchenko, Lanze,
Pennekamp, Engel, Zinnen, Henze, Wehrle. NDSS 2016.
<https://www.comsys.rwth-aachen.de/publication/2016/2016_panchenko_website-fingerprinting-at-internet/>
Introduces the CUMUL classifier and shows that fingerprinting results
degrade sharply at realistic scale. *For us:* useful as a corrective in
both directions — these attacks are real, and their laboratory accuracy
does not transfer directly to a national link.

**Automated Website Fingerprinting through Deep Learning** — Rimmer,
Preuveneers, Juarez, Van Goethem, Joosen. NDSS 2018.
<https://doi.org/10.14722/ndss.2018.23105>
Removes the need for hand-designed features: the classifier learns them.
*For us:* a defence that survives only because nobody has designed a
feature for it is not a defence.

**Deep Fingerprinting: Undermining Website Fingerprinting Defenses with
Deep Learning** — Sirinam, Imani, Juarez, Wright. ACM CCS 2018.
<https://dl.acm.org/doi/10.1145/3243734.3243768>
A convolutional network reaches very high accuracy against undefended
traffic and remains effective against defences that were considered
adequate at the time. *For us:* the reason the threat model refuses to
claim that shaping defeats a classifier built specifically against it.

**Triplet Fingerprinting: More Practical and Portable Website
Fingerprinting with N-shot Learning** — Sirinam, Mathews, Rahman,
Wright. ACM CCS 2019. <https://doi.org/10.1145/3319535.3354217>
Makes such attacks practical with very little labelled data, and portable
across time and network conditions. *For us:* the most uncomfortable
result on this list. An adversary does not need a large labelled corpus
of Chamele0nX traffic to build a working classifier, which is one reason
profiles should not be published.

---

## 2. Active probing and detection of proxies

The second thing a censor does after suspecting a server is talk to it.

**Examining How the Great Firewall Discovers Hidden Circumvention
Servers** — Ensafi, Fifield, Winter, Feamster, Weaver, Paxson. IMC 2015.
<https://dl.acm.org/doi/10.1145/2815675.2815690>
The first detailed measurement of large-scale active probing: suspicious
flows trigger connections from the censor's own infrastructure.
*For us:* the reason an unauthenticated visitor must receive a complete,
ordinary website rather than an error, a timeout or a closed connection.

**How China Detects and Blocks Shadowsocks** — Alice, Bob, Carol,
Beznazwy, Houmansadr. IMC 2020.
<https://dl.acm.org/doi/10.1145/3419394.3423644>
Combines passive length and entropy heuristics with multi-stage active
probing to identify Shadowsocks servers. *For us:* the case study in how
passive suspicion and active confirmation compose.

**How the Great Firewall of China Detects and Blocks Fully Encrypted
Traffic** — Wu et al. USENIX Security 2023.
<https://gfw.report/publications/usenixsecurity23/en/>
Since 2021, traffic that looks uniformly random with no recognisable
handshake is blocked in real time by heuristics that do not identify any
particular protocol. *For us:* the argument against hiding inside
structureless ciphertext, and for hiding inside a protocol that is
genuinely present.

**Detecting Probe-resistant Proxies** — Frolov, Wampler, Wustrow. NDSS
2020.
<https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/>
Probe-resistant proxies can be identified by TCP-level side channels —
how they time out, how much data they will accept before closing —
without ever authenticating. *For us:* the warning that probe resistance
is not achieved by silence, and that behaviour below the application
layer also has a fingerprint. Our server delegates that behaviour to a
real HTTP server rather than implementing its own, which helps but has
not been tested against these techniques.

**Blocking of QUIC by SNI** — Wu et al. USENIX Security 2025.
<https://gfw.report/publications/usenixsecurity25/en/>
The censor decrypts QUIC Initial packets at scale to read the SNI and
block on it. *For us:* relevant to the roadmap's UDP-based cover, and a
reminder that "it is encrypted" and "it is unreadable" are different
claims.

---

## 3. Mimicry protocols, and why they failed

**The Parrot Is Dead: Observing Unobservable Network Communications** —
Houmansadr, Brubaker, Shmatikov. IEEE S&P 2013.
<https://www.ieee-security.org/TC/SP2013/papers/4977a065.pdf>
Systems that achieve unobservability by imitating another protocol fail
structurally: the imitator must be correct on every observable detail,
while the observer needs one discrepancy. *For us:* the single most
important paper on this list, and the reason the design serves a real
site over a real TLS stack instead of imitating one. It also applies to
our shaper, which *is* an imitation — of a distribution rather than a
protocol, but an imitation.

**Seeing through Network-Protocol Obfuscation** — Wang, Dyer, Akella,
Ristenpart, Shrimpton. ACM CCS 2015.
<https://dl.acm.org/doi/10.1145/2810103.2813715>
Demonstrates the above against obfuscation systems that were actually
deployed, using realistic traffic. *For us:* the empirical companion to
the parrot argument.

**SoK: Towards Grounding Censorship Circumvention in Empiricism** —
Tschantz, Afroz, Paxson, et al. IEEE S&P 2016.
<https://censorbib.nymity.ch/pdf/Tschantz2016a.pdf>
Circumvention tools are routinely evaluated against imagined censors
rather than observed ones, and the two differ in ways that matter.
*For us:* the reason the threat model describes what censors are
documented to do rather than what a maximally capable adversary could do.

---

## 4. Traffic shaping as a defence

Chamele0nX's shaper is a member of this family, and a less rigorously
evaluated one than the designs below.

**Walkie-Talkie: An Efficient Defense Against Passive Website
Fingerprinting Attacks** — Wang, Goldberg. USENIX Security 2017.
<https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/wang-tao>
Half-duplex communication plus burst moulding, with measured bandwidth
and latency overheads. *For us:* an early demonstration that the unit of
defence is the burst, not the packet.

**Zero-delay Lightweight Defenses against Website Fingerprinting** —
Gong, Wang. USENIX Security 2020.
<https://www.usenix.org/conference/usenixsecurity20/presentation/gong>
FRONT and GLUE: randomised padding concentrated where it does most good,
with no added latency. *For us:* evidence that a defence which costs no
delay can still be worth something — relevant because our inline burst
pause is capped at 250 ms precisely to protect latency.

**Surakav: Generating Realistic Traces for a Strong Website
Fingerprinting Defense** — Gong, Zhang, Zhang, Wang. IEEE S&P 2022.
<https://cse.hkust.edu.hk/~charlesz/papers/surakav.pdf>
Uses a generative model to produce realistic sending patterns and
regulates buffered data to follow them, evaluated on the live Tor
network. *For us:* the closest published relative to what our shaper
does, and a considerably more rigorous treatment of it. Anyone improving
the shaper should read this first.

**RegulaTor: A Straightforward Website Fingerprinting Defense** —
Holland, Hopper. PETS 2022.
<https://petsymposium.org/popets/2022/popets-2022-0049.php>
Shapes traffic around the observation that real page loads are dominated
by large surges followed by decay. *For us:* the argument for modelling
bursts explicitly, which is what `BurstPattern` in `profile.go` does.

---

## 5. Practical circumvention systems

**HTTPT: A Probe-Resistant Proxy** — Frolov, Wustrow. USENIX FOCI 2020.
<https://www.usenix.org/conference/foci20/presentation/frolov>
A proxy behind a real HTTPS server: unauthenticated requests are served
by the web server, and only an authenticated request is treated as proxy
traffic. *For us:* this is the architecture. Our server's behaviour
toward unauthenticated visitors is the same idea.

**The use of TLS in Censorship Circumvention** — Frolov, Wustrow. NDSS
2019.
<https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_03B-2-1_Frolov_paper.pdf>
Circumvention tools were identifiable by their TLS fingerprints, which
differed from any real browser; introduces uTLS as the fix. *For us:* we
depend on uTLS directly, and inherit its maintenance burden — the
fingerprint has to be updated as browsers move.

**OpenVPN is Open to VPN Fingerprinting** — Xue, Ramesh, Jain,
Kallitsis, Halderman, Crandall, Ensafi. USENIX Security 2022.
<https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen>
OpenVPN, including obfuscated variants, is fingerprinted at scale with
high accuracy and very low false positives. *For us:* the baseline this
design is measured against, and a warning that "obfuscated" is not a
property, it is a claim.

**Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS
Handshakes** — Xue, Kallitsis, Houmansadr, Ensafi. USENIX Security 2024.
<https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting>
A TLS handshake nested inside another encrypted tunnel has a
recognisable shape, independent of which proxy protocol carries it.
*For us:* directly relevant and not fully addressed. Chamele0nX carries
arbitrary tunnelled traffic, including a user's own TLS handshakes, and
the shaper alters the sizes and timing of those inner handshakes but was
not designed against this specific attack. This is an open question for
the project, not a solved one.

**Blocking-resistant communication through domain fronting** — Fifield,
Lan, Hynes, Wegmann, Paxson. PETS 2015.
<https://petsymposium.org/2015/papers/03_Fifield.pdf>
Domain fronting: the TLS SNI names a large provider's domain while the
encrypted HTTP `Host` header routes elsewhere inside it. *For us:*
historically important, and a lesson in dependence — the technique ended
when the providers disabled it, not when a censor defeated it.

**Snowflake, a censorship circumvention system using temporary WebRTC
proxies** — Bocovich, Breault, Fifield, Serene, Wang. USENIX Security
2024.
<https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich>
Many short-lived volunteer proxies, matched by a broker, so there is no
fixed address to block. *For us:* the clearest answer to the problem
Chamele0nX does not solve at all — address blocking — and the reason the
FAQ points users without a server toward it.

---

## 6. Protocols and implementations referenced by this design

Not research papers; specifications and implementations whose behaviour
this project either uses or deliberately differs from.

* **uTLS** — <https://github.com/refraction-networking/utls> — provides
  the browser-accurate `ClientHello` this client sends.
* **obfs4 specification** —
  <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/blob/HEAD/doc/obfs4-spec.txt>
  — the reference design for a shapeless, probe-resistant transport, and
  the approach this project takes the opposite of.
* **Tor pluggable transport specification** —
  <https://spec.torproject.org/pt-spec/> — the interface model for
  swappable transports; relevant to the `CoverProfile` abstraction.
* **Shadowsocks 2022 (SIP022)** — <https://shadowsocks.org/doc/sip022.html>
  — the current AEAD design, and the canonical example of a
  fully-encrypted protocol with no handshake.
* **Xray REALITY** — <https://github.com/XTLS/REALITY> — the widely
  deployed approach to making a server's TLS handshake indistinguishable
  from a real site's, without holding that site's certificate.
* **NaiveProxy** — <https://github.com/klzgrad/naiveproxy> — uses
  Chromium's own network stack rather than imitating it; the strongest
  available answer to fingerprinting, and a higher bar than this project
  reaches.
* **Cloak** — <https://github.com/cbeuw/Cloak> — earlier work on
  authenticating steganographically inside a `ClientHello` while serving
  a decoy site to everyone else.
* **Hysteria 2** — <https://v2.hysteria.network/> — QUIC-based transport
  optimised for lossy links; the performance comparison in
  [COMPARISON.md](COMPARISON.md).
* **AmneziaWG** — <https://docs.amnezia.org/documentation/amnezia-wg/> —
  WireGuard with its packet signatures removed or disguised.

---

## 7. Measurement and reporting

Where blocking events are reported first, usually well before they are
studied.

* **net4people/bbs** — <https://github.com/net4people/bbs> — the forum
  where new blocking behaviour is reported and discussed. Issue
  [#490](https://github.com/net4people/bbs/issues/490) documents
  connection-volume filtering of foreign-hosted TLS in Russia, which is
  the behaviour the optional SNI pool in `sni_pool.go` targets.
* **GFW Report** — <https://gfw.report/> — measurement work on China's
  system, and the source of several papers above.
* **OONI** — <https://ooni.org/> — open measurement data on network
  interference, by country and over time.
* **Censored Planet** — <https://censoredplanet.org/> — longitudinal
  global censorship measurement.
* **CensorBib** — <https://censorbib.nymity.ch/> — the bibliography of
  the field. If something is missing from this page, it is probably
  there.

---

## What is deliberately not cited here

Claims that circulate in community channels about specific detection
thresholds, blocking timers and per-address volume limits are excluded
unless a verifiable source exists. Several such claims informed early
design decisions in this project and turned out to be untraceable. Where
the code acts on one of them — the SNI pool is the clearest case — the
comment in the source says which measurement it came from, and the
[threat model](THREAT-MODEL.md) treats it as perishable rather than as
established fact.
