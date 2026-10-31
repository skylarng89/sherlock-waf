#!/usr/bin/env bash
# M9 acceptance 1: what policy.api adds to a documented request. Starts a full
# control-plane node (sherlock run) with a temporary data directory, creates an
# admin and an API token with the CLI, uploads the OpenAPI document through the
# API (pinned to the node's SPKI hash), imports a configuration with a plain
# site and a policy.api site, then drives POST /payments at a constant arrival
# rate against both and reports the added p50/p95/p99.
#   test/k6/run-api.sh
# Environment: K6_API_RATE (default 200), K6_API_DURATION (default 2m),
# K6_OUT, K6_IMAGE, K6_SHERLOCK_CPUS, K6_ORIGIN_CPUS, K6_CPUS as in run.sh.
# Numbers from a developer machine are not the CI runner's: see docs/plan/benchmarks.md.
set -euo pipefail

cd "$(dirname "$0")/../.."
rate=${K6_API_RATE:-200}
duration=${K6_API_DURATION:-2m}
image=${K6_IMAGE:-grafana/k6:latest}
out=${K6_OUT:-test/k6/out}
sherlock_cpus=${K6_SHERLOCK_CPUS:-0,1}
origin_cpus=${K6_ORIGIN_CPUS:-2,3}
k6_cpus=${K6_CPUS:-4-9}
origin_port=18111
http_port=18112
https_port=18113
control_port=18114
mkdir -p "$out"
out=$(cd "$out" && pwd) # absolute: it is bind-mounted into the container

work=$(mktemp -d)
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# exec makes $! the program's own PID so the cleanup trap really stops it.
pin() { if command -v taskset >/dev/null; then exec taskset -c "$1" "${@:2}"; else exec "${@:2}"; fi; }

CGO_ENABLED=0 go build -trimpath -o "$work/sherlock" ./cmd/sherlock
go build -o "$work/origin" ./test/k6/upstream
pin "$origin_cpus" "$work/origin" -listen "127.0.0.1:${origin_port}" &
pids+=($!)

# Admin account and token, created before the node starts so both use the
# database directly. The token secret is the only thing on stdout.
password=$(openssl rand -hex 24)
printf '%s' "$password" | "$work/sherlock" user create admin --admin --password-stdin --data-dir "$work/data" >/dev/null
token=$("$work/sherlock" token create --user admin --name k6-api --scope read --scope write --expires-in 24h --data-dir "$work/data" 2>/dev/null)

# ES256 key pair and a long-lived bearer token for the protected site.
jwt=$(go run ./test/k6/mintjwt -dir "$work/jwt")

python3 - "$work" "$origin_port" <<'PY'
import sys
work, origin = sys.argv[1], sys.argv[2]
pem = open(f"{work}/jwt/pub.pem").read().strip().splitlines()
pem_block = "\n".join("            " + line for line in pem)
open(f"{work}/sherlock.yaml", "w").write(f"""schema_version: 1
global:
  events: {{ sinks: {{ stdout: false, file: false }} }}
sites:
  - id: plain
    hosts: [plain.localhost]
    tls: {{ mode: none }}
    policy: {{ mode: block }}
    upstreams: {{ targets: ["127.0.0.1:{origin}"] }}
  - id: payments
    hosts: [api.localhost]
    tls: {{ mode: none }}
    policy:
      mode: block
      api:
        enabled: true
        openapi_doc_id: payments
        unknown_path_action: block
        schema_violation_action: block
        jwt:
          - match: {{ paths: ["/payments"] }}
            public_key_pem: |
{pem_block}
            issuer: https://auth.bench.test/
            audiences: [payments-bench]
    upstreams: {{ targets: ["127.0.0.1:{origin}"] }}
""")
PY

"$work/sherlock" run --listen "127.0.0.1:${control_port}" --data-dir "$work/data" \
  --http-port "$http_port" --https-port "$https_port" > "$work/sherlock.log" 2>&1 &
pids+=($!)

# The node logs the SPKI hash of its certificate; that hash is the pin.
pin_hex=""
for _ in $(seq 1 120); do
  pin_hex=$(grep -o '"spki_sha256":"[0-9a-f]*"' "$work/sherlock.log" 2>/dev/null | head -1 | cut -d'"' -f4 || true)
  [[ -n $pin_hex ]] && break
  sleep 0.5
done
[[ -n $pin_hex ]] || { echo "node did not report its certificate pin; see $work/sherlock.log" >&2; exit 1; }
pin_b64=$(python3 -c 'import base64,sys; print(base64.b64encode(bytes.fromhex(sys.argv[1])).decode())' "$pin_hex")
api="https://127.0.0.1:${control_port}/api/v1"

# OpenAPI document through the API. The node's certificate is self-signed, so
# curl trusts that exact certificate and also requires the pinned public key.
openssl s_client -connect "127.0.0.1:${control_port}" -servername 127.0.0.1 </dev/null 2>/dev/null \
  | openssl x509 > "$work/node-cert.pem"
python3 - test/k6/payments-openapi.yaml "$work/doc.json" <<'PY'
import json, sys
json.dump({"name": "payments", "content": open(sys.argv[1]).read()}, open(sys.argv[2], "w"))
PY
doc_status=$(curl -sS -o "$work/doc-response.json" -w '%{http_code}' --cacert "$work/node-cert.pem" --pinnedpubkey "sha256//${pin_b64}" \
  -X PUT -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
  --data-binary "@$work/doc.json" "$api/api-docs/payments")
[[ $doc_status == 2* ]] || { echo "uploading the OpenAPI document failed: HTTP ${doc_status}" >&2; cat "$work/doc-response.json" >&2; exit 1; }

"$work/sherlock" config import "$work/sherlock.yaml" --server "https://127.0.0.1:${control_port}" \
  --token "$token" --tls-pin "$pin_hex"

for _ in $(seq 1 60); do
  curl -s -o /dev/null -H 'Host: plain.localhost' "http://127.0.0.1:${http_port}/" && break
  sleep 0.5
done

# Sanity checks before any load: the protected route must accept a valid
# documented request and refuse the same request without a token.
body='{"amount":1250,"currency":"EUR"}'
check() { # want status, then curl args
  local want=$1; shift
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  [[ $got == "$want" ]] || { echo "sanity check failed: want ${want}, got ${got}: $*" >&2; exit 1; }
}
check 201 -H 'Host: plain.localhost' -H 'Content-Type: application/json' -X POST --data "$body" "http://127.0.0.1:${http_port}/payments"
check 201 -H 'Host: api.localhost' -H 'Content-Type: application/json' -H "Authorization: Bearer ${jwt}" -X POST --data "$body" "http://127.0.0.1:${http_port}/payments"
check 401 -H 'Host: api.localhost' -H 'Content-Type: application/json' -X POST --data "$body" "http://127.0.0.1:${http_port}/payments"
echo "sanity checks passed"

k6run() { # name script env...
  local name=$1 script=$2
  shift 2
  docker run --rm --network host --user "$(id -u):$(id -g)" --cpuset-cpus "$k6_cpus" -v "$PWD/test/k6:/scripts:ro" -v "$out:/out" \
    "$@" "$image" run --quiet --summary-export "/out/${name}.json" "/scripts/${script}" > "$out/${name}.txt" 2>&1 || true
}

echo "== api: POST /payments at ${rate} rps for ${duration}, plain vs policy.api"
k6run api-plain api.js -e "RATE=${rate}" -e "DURATION=${duration}" -e "TARGET=http://127.0.0.1:${http_port}" -e "HOST_HEADER=plain.localhost" -e "TOKEN=${jwt}"
k6run api-protected api.js -e "RATE=${rate}" -e "DURATION=${duration}" -e "TARGET=http://127.0.0.1:${http_port}" -e "HOST_HEADER=api.localhost" -e "TOKEN=${jwt}"

python3 - "$out" <<'PY'
import json, sys
out = sys.argv[1]
def load(n):
    return json.load(open(f"{out}/{n}.json"))["metrics"]
plain, prot = load("api-plain"), load("api-protected")
d, s = plain["http_req_duration"], prot["http_req_duration"]
print(f"{'':6s}{'plain':>10s}{'protected':>10s}{'added':>10s}   (ms)")
res = {}
for label, key in [("p50", "med"), ("p95", "p(95)"), ("p99", "p(99)"), ("max", "max")]:
    added = s[key] - d[key]
    res[label] = {"plain": d[key], "protected": s[key], "added": added}
    print(f"{label:6s}{d[key]:10.3f}{s[key]:10.3f}{added:10.3f}")
for name, m in [("plain", plain), ("protected", prot)]:
    res[f"{name}_failed_rate"] = m["http_req_failed"]["value"]
    res[f"{name}_dropped"] = m.get("dropped_iterations", {}).get("count", 0)
    print(f"{name}: failed rate {m['http_req_failed']['value']:.6f}, dropped iterations {m.get('dropped_iterations', {}).get('count', 0)}")
ok = res["p95"]["added"] <= 1.0
print(f"M9 acceptance 1, p95 added <= 1 ms: {'PASS' if ok else 'FAIL'}")
json.dump(res, open(f"{out}/api-summary.json", "w"), indent=2)
sys.exit(0 if ok else 1)
PY
