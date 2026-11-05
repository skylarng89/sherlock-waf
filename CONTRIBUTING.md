# Contributing to Sherlock WAF

Thanks for helping. Please read this before opening a pull request.

## Before you start

- For anything larger than a small fix, open an issue or discussion first so we can agree on the approach. Design decisions are recorded as ADRs in `docs/architecture/adr/`.
- Check `docs/product/editions.md`: protection features belong here; management/compliance/scale features may belong to the Enterprise edition.

## Development

See `docs/engineering/dev-environment.md`. The short version:

```bash
make setup && make gen && make check
```

## Pull requests

- One logical change per PR, with tests.
- Conventional Commit title, e.g. `fix(waf): handle empty multipart boundary`.
- `make check` must pass. CI must be green.
- Update docs (`docs/user/` and design docs) when behaviour changes.
- Fill in the PR template, including the security checklist.
- You are responsible for every line you submit and must have reviewed and tested it.

## Contributor Licence Agreement

Before we can merge your first PR you must sign the [CLA](CLA.md). The CLA Assistant bot will ask you on the PR. The CLA lets the project be distributed under both the AGPL and a commercial licence while you keep copyright to your contribution.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
