#!/usr/bin/env bash
# NFR-1 / NFR-2 measurement. Builds a release-style Sherlock (no test hooks),
# starts a 1 KB origin, and drives both with k6:
#   latency    200 rps for 2 min, direct vs through Sherlock -> added p50/p95/p99
#   throughput walk the arrival rate up until p99 > 50 ms or requests are dropped
# Sherlock is pinned to K6_SHERLOCK_CPUS (default 0,1, i.e. "a 2 vCPU node"); the
# origin and k6 run on other cores. Numbers from a developer machine are NOT the
# CI runner's: see docs/plan/benchmarks.md.
#   test/k6/run.sh [latency|throughput|all]
set -euo pipefail

cd "$(dirname "$0")/../.."
what=${1:-all}
out=${K6_OUT:-test/k6/out}
sherlock_cpus=${K6_SHERLOCK_CPUS:-0,1}
origin_cpus=${K6_ORIGIN_CPUS:-2,3}
k6_cpus=${K6_CPUS:-4-9}
latency_rate=${K6_LATENCY_RATE:-200}
latency_duration=${K6_LATENCY_DURATION:-2m}
image=${K6_IMAGE:-grafana/k6:latest}
origin_port=18101
sherlock_port=18102
mkdir -p "$out"
out=$(cd "$out" && pwd) # absolute: it is bind-mounted into the container

work=$(mktemp -d)
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# Always called as a background job; exec makes $! the program's own PID so the
# cleanup trap really stops it (a function wrapper would leave it orphaned).
pin() { if command -v taskset >/dev/null; then exec taskset -c "$1" "${@:2}"; else exec "${@:2}"; fi; }

go build -o "$work/origin" ./test/k6/upstream
CGO_ENABLED=0 go build -trimpath -o "$work/sherlock" ./cmd/sherlock

pin "$origin_cpus" "$work/origin" -listen "127.0.0.1:${origin_port}" &
pids+=($!)

cat > "$work/sherlock.yaml" <<YAML
schema_version: 1
global:
  admin: { listen: "off" }
  events: { sinks: { stdout: false, file: false } }
sites:
  - id: bench
    hosts: [bench.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["127.0.0.1:${origin_port}"] }
YAML
pin "$sherlock_cpus" "$work/sherlock" run --config "$work/sherlock.yaml" --http-port "$sherlock_port" \
  --https-port 18443 --data-dir "$work/data" > "$work/sherlock.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null -H 'Host: bench.localhost' "http://127.0.0.1:${sherlock_port}/" && break
  sleep 0.5
done

k6run() { # name script env...
  local name=$1 script=$2
  shift 2
  docker run --rm --network host --user "$(id -u):$(id -g)" --cpuset-cpus "$k6_cpus" -v "$PWD/test/k6:/scripts:ro" -v "$out:/out" \
    "$@" "$image" run --quiet --summary-export "/out/${name}.json" "/scripts/${script}" > "$out/${name}.txt" 2>&1 || true
}

metric() { python3 - "$1" "$2" "$3" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["metrics"]
print(m[sys.argv[2]][sys.argv[3]])
PY
}

if [[ $what == latency || $what == all ]]; then
  echo "== latency: ${latency_rate} rps for ${latency_duration}"
  k6run latency-direct latency.js -e "RATE=${latency_rate}" -e "DURATION=${latency_duration}" -e "TARGET=http://127.0.0.1:${origin_port}"
  k6run latency-sherlock latency.js -e "RATE=${latency_rate}" -e "DURATION=${latency_duration}" -e "TARGET=http://127.0.0.1:${sherlock_port}"
  python3 - "$out" <<'PY'
import json, sys
out = sys.argv[1]
def load(n):
    return json.load(open(f"{out}/{n}.json"))["metrics"]["http_req_duration"]
d, s = load("latency-direct"), load("latency-sherlock")
rows = [("p50", "med"), ("p95", "p(95)"), ("p99", "p(99)"), ("max", "max")]
res = {}
print(f"{'':6s}{'direct':>10s}{'sherlock':>10s}{'added':>10s}   (ms)")
for label, key in rows:
    added = s[key] - d[key]
    res[label] = {"direct": d[key], "sherlock": s[key], "added": added}
    print(f"{label:6s}{d[key]:10.3f}{s[key]:10.3f}{added:10.3f}")
ok95, ok99 = res["p95"]["added"] <= 5, res["p99"]["added"] <= 15
print(f"NFR-1 p95 added <= 5 ms: {'PASS' if ok95 else 'FAIL'}   p99 added <= 15 ms: {'PASS' if ok99 else 'FAIL'}")
json.dump(res, open(f"{out}/latency-summary.json", "w"), indent=2)
sys.exit(0 if ok95 and ok99 else 1)
PY
fi

if [[ $what == throughput || $what == all ]]; then
  echo "== throughput: stepping the arrival rate until p99 > 50 ms"
  best=0
  for rate in 500 1000 1500 2000 3000 4000 6000 8000 12000; do
    k6run "throughput-$rate" throughput.js -e "RATE=${rate}" -e "TARGET=http://127.0.0.1:${sherlock_port}"
    read -r p99 dropped failed < <(python3 - "$out/throughput-$rate.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["metrics"]
print(m["http_req_duration"]["p(99)"], m.get("dropped_iterations", {}).get("count", 0), m["http_req_failed"]["value"])
PY
)
    printf '  %6s rps: p99 %8.2f ms  dropped %s  failed %s\n' "$rate" "$p99" "$dropped" "$failed"
    if python3 -c "import sys; sys.exit(0 if float('$p99') <= 50 and int('$dropped') == 0 and float('$failed') < 0.001 else 1)"; then
      best=$rate
    else
      break
    fi
  done
  echo "highest step with p99 <= 50 ms and no drops: ${best} rps (NFR-2 needs >= 2000)"
  echo "$best" > "$out/throughput-best.txt"
  [[ $best -ge 2000 ]]
fi
