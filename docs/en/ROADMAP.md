# Roadmap

This is what the project knows it is missing, roughly in the order the
gaps hurt. It is not a schedule, and nothing here is promised.

## Known gaps, worst first

**Version negotiation.** There is none. A client and a server that
disagree about the frame layout fail in confusing ways rather than
negotiating down. Every wire change today is a flag day, and deployed
mobile clients update slowly. This blocks almost everything else.

**One server, one profile.** Every user of a given server produces
traffic shaped by the same profile. That is fine against a classifier
looking for VPNs and much less fine against one looking for *this*
protocol, because it makes users of one server look like each other. Per
connection variation exists only in the User-Agent, the SNI choice and
the shaper's own randomness.

**Stream flow control.** The wire format has no way for a receiver to
slow a sender down. A stream whose reader stops consuming now gets reset
after a short grace period, so it can no longer freeze the whole tunnel,
but resetting an honest slow reader is a blunt answer. The real fix is a
window: a `WINDOW_UPDATE` stream frame, credit accounted per stream and
per tunnel, `Stream.Write` blocking when the credit runs out. Stream
types 0x07 and up are unused and an old peer ignores what it does not
recognise, so this can ship without a flag day.

**The server's TLS fingerprint is Go's.** The listener answers with Go's
`crypto/tls`, which is recognisably not the nginx the cover site
imitates, and Go's ServerHello extension order cannot be configured. The
answer is a mode where the server does not terminate its own TLS at all
but forwards an unauthenticated handshake to a real site, the way
REALITY does. That is a different wire protocol. Until then the
documented mitigation is a real front terminating TLS, at the cost of
record shaping.

**Server discovery.** Clients are configured with an address by hand. If
a server's address is blocked, every one of its users is stranded until
someone tells them a new address out of band. This is the single biggest
practical failure mode, and nothing in the protocol addresses it.

**The uTLS fingerprint ages.** The handshake imitates a specific Chrome
version. Real Chrome moves on; an old fingerprint eventually becomes a
rare fingerprint, which is its own signal. Today this is a manual bump.

**Network classification starts with probes.** A taxonomy of censorship
environments and a map from class to preferred cover were written, then
removed: nothing measured the live network, so the class always came
from outside and every class resolved to the one registered cover. If
this is worth having, it begins with measurement, not with names.

**The cover registry has one member.** `CoverProfile` describes an
extension point that is never exercised: the only registered cover is
opened inline in `Transport.connect` rather than through the interface.
Either a second cover justifies the abstraction or the abstraction
should go.

## Things worth building

**A second cover.** The design's real claim is that the cover is
replaceable. Nothing proves that until something other than an HTTP/2
dashboard carries traffic. A call-like cover over UDP would test the
abstraction and would reach networks where TCP to foreign hosts is
throttled.

**Automatic profile refresh.** A profile is a photograph of a site at a
moment. Sites change. A server that re-measured its own cover site
periodically and reloaded the profile would stay accurate without an
operator noticing.

**Multi-server clients.** A client holding several endpoints that tries
them in order, remembers which worked, and does not hammer a dead one is
straightforward and would blunt address blocking considerably.

**A packaged mobile client.** The binding exists, an app does not. See
[CLIENTS.md](CLIENTS.md) for what such an app has to do.

**Measurement that other people can reproduce.** The performance numbers
in this repository were measured by the author, on the author's path,
with the author's server. That is not evidence. A repeatable harness that
anyone can run from their own network would be worth more than any
optimisation.

## Things deliberately not planned

**New cryptography.** The protocol uses X25519, HKDF-SHA256 and
AES-256-GCM because they are boring and correct. Nothing here needs a
novel construction, and a novel construction would need a review budget
this project does not have.

**A hosted service in this repository.** Accounts, payments, server
selection and support belong to whoever runs a service, not to the
transport.

**Obfuscating away from TLS.** Anything that does not look like TLS on
port 443 loses the property the whole design is built on.

## Contributing to any of this

Open an issue before starting on the first six items; they touch the wire
format or the security posture, and a large pull request that lands
sideways helps nobody. See [CONTRIBUTING.md](../../CONTRIBUTING.md).
