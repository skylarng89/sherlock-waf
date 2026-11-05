#!/usr/bin/env bash
# Compare two `go test -bench` outputs with benchstat and fail when any
# benchmark got statistically significantly slower by more than THRESHOLD
# percent (default 10). Usage: bench-gate.sh base.txt head.txt
set -euo pipefail

base=${1:?usage: bench-gate.sh base.txt head.txt}
head=${2:?usage: bench-gate.sh base.txt head.txt}
threshold=${THRESHOLD:-10}

benchstat="go tool -modfile=tools/go.mod benchstat"
$benchstat "$base" "$head" || true

# CSV sections start with a header row whose second field is the unit; only
# the sec/op section gates (B/op and allocs/op are reported, not enforced).
# benchstat prints "~" for differences that are not statistically significant.
$benchstat -format csv "$base" "$head" 2>/dev/null | awk -F, -v t="$threshold" '
  $2 == "sec/op" { in_time = 1; next }
  $2 ~ /^(B\/op|allocs\/op)$/ { in_time = 0; next }
  in_time && $1 != "" && $1 != "geomean" && $6 ~ /^\+[0-9.]+%$/ {
    pct = substr($6, 2, length($6) - 2) + 0
    if (pct > t) { printf "REGRESSION %s: %s (limit +%s%%)\n", $1, $6, t; bad = 1 }
  }
  END { exit bad }
'
echo "bench-gate: no significant regression over ${threshold}%"
