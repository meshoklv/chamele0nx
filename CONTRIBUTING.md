# Contributing

[По-русски](CONTRIBUTING.ru.md)

Thanks for looking. This is a small project with a specific job, so a
few things are worth knowing before you spend time on a change.

## Before you start

- **Security bugs never go in an issue.** Read [SECURITY.md](SECURITY.md)
  first. A public description of a way to detect this traffic is a gift
  to the people doing the detecting.
- **Open an issue before a large change.** A protocol change that breaks
  the wire format affects every deployed client, and those clients often
  belong to people who cannot easily update.
- **Small, focused pull requests get merged. Large ones stall.**

## Development setup

```bash
git clone https://github.com/meshoklv/chamele0nx
cd chamele0nx
make build      # binaries in ./bin
make check      # gofmt, vet, lint, build, race tests, hygiene: the gate CI runs
```

You need Go 1.26 or newer. There is nothing else to install; the
project has five direct dependencies and no code generation step.

One exception: `make check` runs the tests under the race detector, which
needs cgo and therefore a C compiler. On a minimal container without one,
`go test -race` fails with `-race requires cgo` before running anything.
Install a C compiler, or run `make test` and leave the race pass to CI.

## The rules that actually matter

**1. The wire format is a compatibility contract.**
Frame types, header layouts, HKDF info strings, cookie formats and the
authentication handshake are load-bearing. A deployed client speaks the
version it shipped with. Any change here needs a version negotiation
story in the same pull request, or it does not land.

**2. Never make the traffic more regular.**
The whole protocol exists to avoid producing a distinguishable pattern.
Optimisations that make record sizes more uniform, remove jitter, or
coalesce bursts trade away the only property that matters. If a change
makes it faster, say how you checked it did not make it more visible.

**3. Fail closed, loudly.**
When certificate pinning, authentication or shaping cannot be applied,
the correct behaviour is a clear error, never a quiet fallback to the
unprotected path.

**4. Nothing identifying goes into logs.**
No client IPs, no secrets, no cookies, no chosen SNI values. Log
structure and counts, not people.

**5. No production data in the repository.**
No real domains, no server addresses, no captured site profiles, no
certificate pins. Examples use `vpn.example.com`. Traffic profiles you
captured from a real site are yours to keep private: publishing one lets
a censor build a classifier aimed at exactly that site.

## Code style

- `gofmt -s` formatting, enforced by CI.
- Comments explain *why*, not *what*. The existing code does this well;
  match it.
- Comments are in English, so that contributors who do not read Russian
  can review protocol-critical code.
- Exported identifiers carry doc comments.
- New behaviour comes with a test. Protocol-level behaviour comes with a
  test that would fail if the wire format changed.

## Commit messages

One line of summary in the imperative, then a blank line, then why the
change is needed. Reference an issue if there is one.

```
shaper: keep record sizes inside the profile histogram under backpressure

Under a full write buffer the shaper fell back to maximum-size records,
which produced a flat 16 KB tail that the profile never contains.
```

## Testing a change to shaping

A change to the shaper or a profile is not done until you have looked at
what it produces:

```bash
# generate synthetic traffic from a profile and test it against itself
./bin/chamele0nx-validator -profile deploy/profiles/saas-fast.example.json -generate 1000
```

The validator runs a Kolmogorov-Smirnov test and a chi-squared test on
the record size distribution, against the sizes the profile actually puts
on the wire — jitter and record-size clamping included, not the bucket
histogram on its own.

Both the verdict line and the exit code are usable as a gate, so this can
sit in CI. Read the D-statistic as well: compare it against the same
number from before your change, because a change that moves it upward is
a regression even when throughput improved.

Note that `-generate` judges at α = 1e-4 rather than the customary 0.05,
and `-samples` keeps 0.05. In generate mode the samples come from the
profile's own sampler, so the hypothesis under test is true by
construction and at 0.05 a correct model would fail about one run in
twenty — measured, not assumed: twenty runs of `saas-stealth` put the
p-values evenly across the interval with exactly one below 0.05. A gate
that fails on schedule gets ignored, so the self-test asks the stricter
question instead. Pass `-alpha` to override either default.

If you change the shaper's jitter, change `RecordJitterPercent` — the one
constant both the write path and the validator's reference are built
from. Splitting them apart is what once made this tool report FAIL for
every profile ever shipped, for two years, on a defect in the tool rather
than in any profile.

## Licence of contributions

The project is AGPL-3.0-or-later. By opening a pull request you agree
your contribution is licensed under those terms. There is no CLA.
