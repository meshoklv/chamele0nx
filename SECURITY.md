# Security policy

[По-русски](SECURITY.ru.md)

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

This project is used to reach the open internet from networks where that
is actively prevented. A publicly filed bug that describes how to
distinguish Chamele0nX traffic from ordinary HTTPS is not a bug report,
it is a blocking recipe handed to whoever is doing the blocking.

Report privately through GitHub's **Security → Report a vulnerability**
form on this repository. That opens a private advisory visible only to
the maintainers.

Please include:

- what you observed, and what you expected instead;
- the smallest reproduction you have, ideally a packet capture or a test
  case rather than prose;
- the commit or release you tested;
- whether you have shared the finding anywhere else, and when you intend
  to publish.

## What counts as a vulnerability here

Beyond the usual memory-safety and crash categories, treat all of these
as security bugs:

| Class | Example |
|---|---|
| **Distinguisher** | Any statistic that separates shaped traffic from real traffic of the cover site with useful accuracy. |
| **Active probe** | A request an outside party can send to the server that gets a different answer than a real site would give. |
| **Authentication** | Anything that reveals whether a given secret is valid, including through timing. |
| **Key handling** | Session keys living longer than the session, reaching disk, or reaching logs. |
| **Metadata leak** | Client IPs, cookies, SNI choices, or secrets appearing in logs or telemetry. |
| **Downgrade** | Any path that silently disables record shaping or certificate pinning. |

## Response

We aim to acknowledge a report within 72 hours and to agree a disclosure
timeline with you in the first exchange. The default is 90 days from
acknowledgement to public disclosure, shorter if a fix ships sooner and
longer only by mutual agreement.

Credit is given in the advisory and the changelog unless you ask us not
to.

## Operator security

If you run a server, the operational hardening checklist in
[docs/en/OPERATIONS.md](docs/en/OPERATIONS.md) is part of the security
story, not an optional extra. A perfectly shaped tunnel on a box with
password SSH and an open management port protects nobody.
