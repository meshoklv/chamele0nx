## What this changes

<!-- One paragraph. Why, not just what. -->

## Checklist

- [ ] `make check` passes locally (vet, lint, race tests)
- [ ] New behaviour has a test
- [ ] No production domains, addresses, secrets, certificate pins or
      captured site profiles are included
- [ ] Nothing identifying was added to log output

## Wire format

- [ ] This change does **not** touch the wire format
- [ ] This change touches the wire format, and version negotiation is
      handled in this pull request

<!-- If it touches the wire format, describe what a client from the
     previous release does when it meets a server with this change. -->

## Effect on detectability

<!-- Required for any change to the shaper, profiles, cover behaviour,
     timing, or TLS parameters. State what you measured and how. Write
     "none" only if the change cannot affect what an observer sees. -->
