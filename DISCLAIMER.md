# Disclaimer

[По-русски](DISCLAIMER.ru.md)

## Nature of this project

This repository contains research software: an implementation of a network
transport protocol, published so that its design can be examined,
criticised and reproduced. It is not a product, not a service, and not an
offer of one. No infrastructure is operated for anyone by the authors of
this repository. There is no server list, no directory, no account, and
no way to use this software without providing your own host.

## No warranty

This software is provided "as is", without warranty of any kind, express
or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, non-infringement, and
any warranty as to the effectiveness, reliability or undetectability of
the mechanisms it implements. Sections 15 and 16 of the GNU Affero
General Public License version 3 govern in full.

Specifically and without limitation, the authors make no representation
that traffic produced by this software is indistinguishable from any
other traffic, under any conditions, against any observer, now or in the
future. No independent review of the cryptography, the protocol or the
implementation has been carried out. Claims about behaviour in this
repository describe what the code is intended to do, and are not
assurances about outcomes.

## Limitation of liability

To the maximum extent permitted by applicable law, the authors and
contributors shall not be liable for any claim, damage, loss or other
liability, whether in contract, tort or otherwise, arising from, out of
or in connection with this software or its use, including any consequence
of the software failing to behave as described.

## Responsibility of the user

Anyone who builds, runs, deploys, modifies or distributes this software
does so on their own responsibility and is solely responsible for
determining whether doing so is lawful where they are. The authors do not
and cannot advise on that question. Nothing in this repository is legal
advice, and nothing in it should be read as encouragement to do anything.

## Dependency licensing

One dependency, `github.com/bogdanfinn/fhttp`, ships without a licence
file — not in the published module, not in its repository, and not in the
fork it was taken from. It is a fork of Go's `net/http`, so the inherited
code remains under the Go Authors' BSD licence, but the fork's own
changes carry no grant at all.

What that means in practice: publishing or reading this repository's
source is unaffected, because the dependency is referenced by module path
and never copied here. Distributing **compiled binaries** is a different
matter — a binary contains that code, and the AGPL obliges whoever
distributes it to supply the corresponding source under the AGPL, which
cannot be done for code that grants no rights. Anyone building binaries
for others should resolve that first.

Replacing the dependency is on the roadmap; it exists solely to reproduce
Chrome's HTTP/2 fingerprint, which the standard library cannot express.

## Cryptography and export

This distribution includes cryptographic software. It uses X25519 key
agreement, HKDF-SHA256, AES-256-GCM and HMAC-SHA256 through Go's standard
library and `golang.org/x/crypto`; it implements no cryptographic primitive
of its own.

The import, possession, use and re-export of encryption software is
restricted or prohibited in some countries. Anyone who downloads, builds,
runs or redistributes this software is responsible for checking the laws
that apply where they are, and for complying with them. The authors make no
representation that doing any of those things is lawful in any particular
place.

Publication here is of open cryptographic source code, which many
jurisdictions treat differently from a compiled product — but that is a
statement about how the source is published, not a clearance for any
particular use, destination or person. Sanctions and embargo rules apply
independently of this licence and are not waived by it.

## Trademarks

Domain names that appear in the source, including those in the SNI
substitution pool and the example decoy list, belong to third parties who
have neither endorsed nor been consulted about this software. Naming a
host in a TLS `ClientHello` neither contacts it nor claims any
association with it, but an operator should understand that they are
placing someone else's name on the wire.

"Chamele0nX" here describes the camouflage behaviour the transport
implements. It is not affiliated with, endorsed by, or derived from any
company using a similar name for a product of its own.
