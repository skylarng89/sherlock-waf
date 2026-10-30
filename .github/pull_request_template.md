## What and why

<!-- Milestone task ID(s), e.g. M5-T6, and a short description -->

## Requirements

<!-- FR-/NFR- IDs this delivers or affects -->

## How it was tested

<!-- Commands run and results; screenshots for UI -->

## Security checklist

- [ ] I read every line of the diff in security-sensitive paths (see docs/security/secure-development.md).
- [ ] Tests cover failure paths, not only the happy path.
- [ ] No new network call on the request path.
- [ ] No new dependency, or it is justified below (licence, maintenance, size).
- [ ] New API routes declare `x-sherlock-permission`.
- [ ] Error messages and logs leak nothing sensitive.
- [ ] Threat-model items for this area re-checked.

## Docs

- [ ] User docs updated (docs/user/)
- [ ] Design docs updated if behaviour changed
