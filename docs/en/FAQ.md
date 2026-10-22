# Frequently asked questions

Short answers. Where an answer is "we do not know", it says that.
The long version of most of this is in
[THREAT-MODEL.md](THREAT-MODEL.md) and [COMPARISON.md](COMPARISON.md).

---

### How is this different from a VPN?

Functionally it does the same job: your traffic leaves from somewhere
else. The difference is what the network in between sees. A VPN produces
a recognisable protocol and a long, flat stream of maximum-size packets;
Chamele0nX produces an ordinary HTTPS session to an ordinary website
whose record sizes and burst timing are shaped to look like that
website's real traffic. It is a transport, not a product — there is no
app, no account and no server list.

### Will this get blocked?

Eventually, if enough people use one server. The most likely way is not
that anyone breaks the traffic analysis: it is that the server's IP
address is identified and dropped, which requires no analysis at all.
Plan for the address to be replaced periodically. Nothing in this
repository does that for you.

### Can I use it without running my own server?

No. There is no public infrastructure, no bridge pool and no volunteer
network. You need a host, a domain name and a TLS certificate. If that is
not possible for you, Snowflake is designed for exactly your situation
and needs nothing but a browser.

### What does it cost to run?

The software is free. You pay for a small virtual server and a domain
name. A single modest instance is enough for a handful of users; the cost
is whatever your provider charges, typically a few dollars a month plus
the domain. Bandwidth is usually the variable that bites first.

### Is this safer than Tor?

No — it is a different thing. Tor gives you anonymity: no single relay
knows both who you are and where you are going. Chamele0nX gives you one
hop, and the operator of that hop sees everything. If your concern is a
national filter and you trust whoever runs the server, this is
appropriate. If your concern is being identified, use Tor.

### Can someone tell I am using it?

A network observer sees an HTTPS connection to a website. Whether they
can tell it is a tunnel depends on how hard they look and on what they
already suspect. Against bulk classification the design is meant to blend
in; against an adversary studying your traffic specifically, assume the
answer is yes. Read the section on targeted surveillance in
[THREAT-MODEL.md](THREAT-MODEL.md) before relying on this in a situation
where being wrong is dangerous.

### Could I get in trouble for using it?

That depends entirely on where you are, and this project cannot advise
you. In some places using circumvention tools is unremarkable; in others
it is an offence, or the fact of using one is itself treated as
suspicious. The technical properties of this software do not change the
legal situation you are in.

### Why can't I publish my traffic profile?

A profile is a precise description of what your traffic will look like:
the record-size histogram, the burst lengths, the pauses. Publishing it
hands anyone who wants to build a classifier a labelled training target.
The example profiles in this repository exist to document the file
format. Measure your own from your own cover site, and keep it to
yourself.

### Why AGPL rather than something permissive?

Because in this field a modified, unpublished fork is a security problem,
not a business model. If someone runs a changed version as a service,
their users cannot check what changed — and a small change to a shaper or
an authentication path can quietly remove the property the whole design
exists for. The AGPL requires that those modifications be published. You
may run it, change it and sell access to it; you may not do so with
secret changes.

### Is there a mobile app?

Not from this repository. There are gomobile bindings under `mobile/`,
and an out-of-tree iOS client uses them, but no packaged app ships here.
Building one means writing the platform VPN integration yourself — see
[CLIENTS.md](CLIENTS.md), which lists what such a client has to do,
including a routing detail that will silently defeat the decoy traffic if
you get it wrong.

### Does UDP work? What about QUIC?

Yes, with caveats. The local SOCKS5 proxy accepts UDP ASSOCIATE, and
datagrams are carried inside the same HTTP/2 connection as separate
streams (`transport/chamele0nx/udp_client.go`). The carrier itself is TCP,
so UDP traffic inherits TCP's head-of-line blocking and retransmission
behaviour — QUIC-based applications will work but will not get QUIC's
loss-recovery benefits.

### Does IPv6 work?

Not as a target inside the tunnel. The SOCKS5 layer rejects literal IPv6
destination addresses, on both the TCP and UDP paths, because the tunnel
carries IPv4 only and letting an IPv6 target through would send that flow
outside the tunnel (`chamele0nx.go` and `persistent.go` for TCP,
`udp_client.go` for UDP). Hostnames are
fine — they are resolved at the server end, which is what you want
anyway. Use `socks5h://` rather than `socks5://` so your client does not
resolve names locally.

### Why is it not faster?

Two reasons. The shaper deliberately fragments writes into
profile-sized records and pauses between bursts, which costs throughput
by design — flat, maximum-size records are exactly the pattern it exists
to avoid. And everything runs over a single TCP connection, so a lossy
path hurts more than it would with a UDP-based protocol. If you need
speed on a bad link, Hysteria 2 is built for that and this is not.

### What throughput should I expect?

Roughly 20 Mbit/s was measured over one long-haul path, where the route
rather than the protocol was the limit. That is a single anecdote from
the author's own deployment, not a benchmark, and your result will depend
on your route, your host and your profile. Nobody outside the project has
reproduced any performance figure here.

### How many users can share one server?

In practice, everyone on one server shares one secret: the library can
check a request against several, but the shipped `chamele0nx-server`
registers exactly one. Operationally the limit is much lower than any
number of secrets would suggest,
because every user adds traffic volume to a single address, and volume to
one address is one of the cheapest signals a censor can act on. Keep it
small, know who they are, and run more servers rather than more users per
server.

### What happens if the censor blocks my server's address?

Everyone using it is offline until you give them a new address by some
other means. There is no discovery mechanism, no fallback list and no
address rotation in this repository. This is the single biggest practical
weakness of the design, and it is stated as such in
[THREAT-MODEL.md](THREAT-MODEL.md) and [ROADMAP.md](ROADMAP.md).

### Does it work in China? In Iran?

Unknown — it has not been tested there. The only deployment we have data
from is a single server reached from one censored network, and one
network's behaviour does not generalise. Different countries filter in
different ways, and some of what this design does is aimed at behaviour
observed in one country that may not exist elsewhere. If you test it
somewhere new, we would like to know what happened.

### Has it been audited?

No. Nobody outside this project has reviewed the cryptography, the
protocol or the implementation. The test suite was written by the same
people who wrote the code, which establishes that it behaves as intended
and nothing more. Treat every security claim in this repository
accordingly.

### How does authentication work if there is no login?

The client sends a cookie containing
`HMAC-SHA256(secret, five-minute time bucket || server id)`, formatted to
look like whatever session cookie the cover site's framework would set
(`transport/chamele0nx/auth.go`). The server accepts the current and the
previous bucket, so a captured cookie is useful for roughly ten minutes.
There is no username, no password and no failed-login response — a
request that does not authenticate simply gets the website.

### What does someone see if they just open the site in a browser?

The cover site. There is no path that behaves differently for a browser,
no port that answers differently, and no error that reveals the server
does anything else. An unauthenticated POST to the tunnel's API path gets
a plausible JSON response whose length varies between calls, so probing
it twice does not reveal a constant.

Unknown paths get the cover site's own `404.html` when the directory
ships one, which `deploy/cover-site` does. Without that file the fallback
is Go's static file server, whose 404 body is the literal string
`404 page not found` — a WordPress or Django site would not say that. It
does not name the server as a tunnel, but it does say the site is not what
its cover story claims. Ship a 404 page, and choose a cover story that a
plain static server can carry.

### Do I need a real website, or will a placeholder do?

You need a real one. The premise of the design is that the server *is* a
website which also carries a tunnel. A single default page at a
month-old domain is suspicious before any traffic analysis begins,
and certificate transparency logs are public and searchable. This is the
assumption most likely to be quietly violated in practice.

### Can I use a CDN or a reverse proxy in front of it?

Not usefully. The server must control TLS termination, because the whole
mechanism is about the sizes and timing of the TLS records it emits.
Anything that terminates TLS and re-emits it destroys the shaping.

### Why Chrome specifically, for the TLS and HTTP/2 fingerprints?

Because it is the most common browser, so its fingerprint is the least
remarkable one to present. The cost is that Chrome moves every few weeks
and the imitation has to be updated by hand; an old Chrome fingerprint
eventually becomes a rare fingerprint, which is its own signal. This is
listed as a known weakness rather than a solved problem.

### Can I contribute?

Yes — read [CONTRIBUTING.md](../../CONTRIBUTING.md) first. The short
version: small pull requests, nothing that makes the traffic more
regular, nothing identifying in logs, and security problems go through a
private advisory rather than a public issue. The items in
[ROADMAP.md](ROADMAP.md) that touch the wire format are worth an issue
before any code.

### Something is broken. Where do I report it?

Ordinary bugs go to the issue tracker. Anything with security or
detectability implications goes through a private advisory instead — see
[SECURITY.md](../../SECURITY.md). A public issue describing a way to
distinguish this traffic helps a censor faster than it helps a user.
