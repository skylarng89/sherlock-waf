#!/usr/bin/env bash
# Write dist/release-manifest.json: version, embedded CRS version, minimum
# version an upgrade may start from, and the sha256 of every release artefact
# (taken from GoReleaser's checksums.txt). The workflow signs it with cosign
# and attaches it to the release, so `sherlock update` can verify it.
#   scripts/release-manifest.sh <dist dir> <version>
set -euo pipefail

dist=${1:?usage: release-manifest.sh <dist dir> <version>}
version=${2:?usage: release-manifest.sh <dist dir> <version>}
min_upgrade_from=${MIN_UPGRADE_FROM:-0.1.0}
root=$(cd "$(dirname "$0")/.." && pwd)

crs=$(sed -n 's/^const CRSVersion = "\(.*\)"$/\1/p' "$root/internal/dataplane/waf/waf.go")
[[ -n $crs ]] || { echo "release-manifest: cannot read CRSVersion" >&2; exit 1; }
checksums=$dist/checksums.txt
[[ -s $checksums ]] || { echo "release-manifest: $checksums missing or empty" >&2; exit 1; }

python3 - "$checksums" "$version" "$crs" "$min_upgrade_from" "$dist/release-manifest.json" <<'PY'
import json, sys
checksums, version, crs, minimum, out = sys.argv[1:]
files = {}
for line in open(checksums):
    line = line.strip()
    if line:
        digest, name = line.split(None, 1)
        files[name.strip().lstrip("*")] = digest
json.dump({
    "schema": 1,
    "version": version,
    "crs_version": crs,
    "min_upgrade_from": minimum,
    "artifacts": dict(sorted(files.items())),
}, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
echo "wrote $dist/release-manifest.json"
