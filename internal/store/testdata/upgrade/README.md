# Upgrade fixtures

One directory per released version, used by `upgrade_test.go` to prove that a
configuration written by an earlier release still loads (the automated N-2 check
in docs/release/versioning.md).

Each directory holds:

- `config.yaml`: a representative configuration the release accepted.
- `snapshot.json`: the snapshot **that release itself** stores for it. Generate it
  with the released code, never with the current tree: check out the tag, then run
  `config.Snapshot(config.Parse(config.yaml))` (or `sherlock config export` against
  a node running that release and save the stored snapshot).

Add `vX.Y.Z/` at every release and never edit an existing one: a fixture that must
change means a release broke compatibility, which needs a migration instead.
