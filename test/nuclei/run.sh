#!/usr/bin/env bash
# Run nuclei web-vulnerability templates against OWASP Juice Shop twice: directly
# (what is actually exploitable) and through Sherlock in block mode, then report
# which findings Sherlock stopped. Expects `make e2e-up` to have run.
#   test/nuclei/run.sh            writes test/nuclei/out/{direct,sherlock}.jsonl and prints a summary
set -euo pipefail

cd "$(dirname "$0")/../.."
tags=${NUCLEI_TAGS:-sqli,xss,rce,lfi,ssrf,cmdi,ssti,injection,redirect}
out=${NUCLEI_OUT:-test/nuclei/out}
image=${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}
direct="http://127.0.0.1:${JUICE_DIRECT_PORT:-13000}"
# Scan Sherlock by hostname, as a browser would: a numeric-IP Host header trips
# CRS rule 920350 (+3 anomaly points) on every request and skews the result.
via="http://juice.localhost:${SHERLOCK_HTTP_PORT:-18080}"
mkdir -p "$out"
out=$(cd "$out" && pwd) # absolute: it is bind-mounted into the container

# Generic fuzzing ("DAST") templates only run with -dast and need URLs that carry
# parameters to inject into; Juice Shop is a single-page app, so scanning its
# root finds nothing. targets.txt lists real parameterised endpoints.
scan() { # name base-url
  sed "s|@BASE@|$2|" test/nuclei/targets.txt | grep -v '^#' > "$out/targets-$1.txt"
  docker run --rm --network host --add-host juice.localhost:127.0.0.1 \
    -v sherlock-nuclei-templates:/root/nuclei-templates \
    -v "$out:/out" "$image" \
    -l "/out/targets-$1.txt" -dast -t /root/nuclei-templates/dast/vulnerabilities \
    -tags "$tags" -jsonl -o "/out/$1.jsonl" -silent -nc \
    -rate-limit 150 -concurrency 25 -timeout 8 -retries 0 -disable-update-check
}

: > "$out/direct.jsonl"; : > "$out/sherlock.jsonl"
scan direct "$direct"
scan sherlock "$via"

python3 - "$out" <<'PY'
import json, sys, collections
out = sys.argv[1]
def load(name):
    findings = {}
    for line in open(f"{out}/{name}.jsonl"):
        line = line.strip()
        if not line:
            continue
        f = json.loads(line)
        # Identify a finding by template and request path, not by host.
        url = f.get("matched-at", "").split("://", 1)[-1].split("/", 1)[-1]
        path = url.split("?", 1)[0]
        findings[(f["template-id"], path, f.get("matcher-name") or "")] = f
    return findings

d, s = load("direct"), load("sherlock")
blocked = set(d) - set(s)
by_tag = collections.defaultdict(lambda: [0, 0])
for key, f in d.items():
    tags = f.get("info", {}).get("tags") or []
    for t in tags:
        by_tag[t][0] += 1
        by_tag[t][1] += key in blocked
print(f"\nexploitable directly: {len(d)}   still found through Sherlock: {len(s)}   stopped: {len(blocked)}")
if d:
    print(f"detection rate: {100 * len(blocked) / len(d):.1f}% ({len(blocked)}/{len(d)})")
print("\nper tag (stopped / exploitable):")
for t, (n, b) in sorted(by_tag.items(), key=lambda kv: -kv[1][0]):
    print(f"  {t:20s} {b:3d} / {n:3d}")
missed = sorted(set(d) & set(s))
if missed:
    print("\nnot stopped:")
    for tid, path, _ in missed:
        print(f"  {tid:45s} /{path[:70]}")
json.dump({"direct": len(d), "sherlock": len(s), "stopped": len(blocked), "missed": [list(k) for k in missed]},
          open(f"{out}/summary.json", "w"), indent=2)
PY
