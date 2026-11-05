#!/usr/bin/env bash
# OWASP ZAP baseline scan (spider + passive rules; it does not attack) against
# Juice Shop directly and through Sherlock. Expects `make e2e-up`.
#   test/zap/run.sh   writes test/zap/out/{direct,sherlock}.json and prints alert counts by risk
set -euo pipefail

cd "$(dirname "$0")/../.."
out=${ZAP_OUT:-test/zap/out}
image=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}
minutes=${ZAP_MINUTES:-1}
direct="http://127.0.0.1:${JUICE_DIRECT_PORT:-13000}"
# By hostname, as a browser would (a numeric-IP Host header trips CRS 920350).
via="http://juice.localhost:${SHERLOCK_HTTP_PORT:-18080}"
mkdir -p "$out"
out=$(cd "$out" && pwd) # absolute: it is bind-mounted into the container
chmod 777 "$out"        # the ZAP image runs as a non-root user

scan() { # name target
  # -I: findings do not fail the script; the report is what we record.
  docker run --rm --network host --add-host juice.localhost:127.0.0.1 -v "$out:/zap/wrk:rw" "$image" \
    zap-baseline.py -t "$2" -m "$minutes" -J "$1.json" -I > "$out/$1.log" 2>&1 || true
}

scan direct "$direct"
scan sherlock "$via"

python3 - "$out" <<'PY'
import json, sys
out = sys.argv[1]
names = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
def alerts(name):
    d = json.load(open(f"{out}/{name}.json"))
    res = {}
    for site in d.get("site", []):
        for a in site.get("alerts", []):
            res[a["name"]] = (names.get(str(a.get("riskcode")), "?"), len(a.get("instances", [])))
    return res
d, s = alerts("direct"), alerts("sherlock")
def counts(a):
    c = {}
    for risk, _ in a.values():
        c[risk] = c.get(risk, 0) + 1
    return c
print(f"alert types   direct: {counts(d)}")
print(f"alert types sherlock: {counts(s)}")
print("\nonly directly:", sorted(set(d) - set(s)))
print("only through Sherlock:", sorted(set(s) - set(d)))
json.dump({"direct": counts(d), "sherlock": counts(s), "only_direct": sorted(set(d) - set(s)),
           "only_sherlock": sorted(set(s) - set(d))}, open(f"{out}/summary.json", "w"), indent=2)
PY
