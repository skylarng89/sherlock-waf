#!/usr/bin/env bash
# M11 acceptance 1: credential-stuffing simulation. Starts Sherlock with login
# protection and a stub origin whose login fails for any password but
# "correct horse", then runs test/k6/login-stuffing.js: 50 usernames x 1,000
# passwords from 200 source addresses, plus one ordinary customer who must always
# sign in. Passes when no account is guessed at more than its threshold (plus
# slack for requests already in flight), nearly all guesses are refused, and the
# customer's logins all succeed.
#   test/k6/run-login.sh
# Environment: K6_OUT, K6_IMAGE, K6_SHERLOCK_CPUS, K6_ORIGIN_CPUS, K6_CPUS as in
# run.sh; K6_LOGIN_PER_USERNAME (default 5), K6_LOGIN_PER_IP (default 20).
# Needs Docker for the k6 image. Numbers from a developer machine are not the CI runner's.
set -euo pipefail

cd "$(dirname "$0")/../.."
out=${K6_OUT:-test/k6/out}
image=${K6_IMAGE:-grafana/k6:latest}
sherlock_cpus=${K6_SHERLOCK_CPUS:-0,1}
origin_cpus=${K6_ORIGIN_CPUS:-2,3}
k6_cpus=${K6_CPUS:-4-9}
per_username=${K6_LOGIN_PER_USERNAME:-5}
per_ip=${K6_LOGIN_PER_IP:-20}
origin_port=18201
sherlock_port=18202
mkdir -p "$out"
out=$(cd "$out" && pwd) # absolute: it is bind-mounted into the container

work=$(mktemp -d)
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# Always called as a background job; exec makes $! the program's own PID so the
# cleanup trap really stops it.
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
  trusted_proxies: ["127.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
sites:
  - id: login
    hosts: [login.localhost]
    tls: { mode: none }
    upstreams: { targets: ["127.0.0.1:${origin_port}"] }
    policy:
      mode: block
      bot: { enabled: true }
      login_protection:
        enabled: true
        endpoints: [{ path: /api/login, username_field: email }]
        thresholds: { per_ip: ${per_ip}, per_username: ${per_username}, per_device: 100, window: 10m }
        action: challenge
YAML
pin "$sherlock_cpus" "$work/sherlock" run --config "$work/sherlock.yaml" --http-port "$sherlock_port" \
  --https-port 18443 --data-dir "$work/data" > "$work/sherlock.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do
  curl -s -o /dev/null -H 'Host: login.localhost' "http://127.0.0.1:${sherlock_port}/" && break
  sleep 0.5
done

# Sanity checks before any load: a right password signs in, a wrong one is a 401.
got=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: login.localhost' -H 'X-Forwarded-For: 192.0.2.1' \
  -d 'email=sanity@bank.test&password=correct horse' "http://127.0.0.1:${sherlock_port}/api/login")
[[ $got == 200 ]] || { echo "sanity check failed: right password gave ${got}" >&2; exit 1; }
got=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: login.localhost' -H 'X-Forwarded-For: 192.0.2.1' \
  -d 'email=sanity@bank.test&password=wrong' "http://127.0.0.1:${sherlock_port}/api/login")
[[ $got == 401 ]] || { echo "sanity check failed: wrong password gave ${got}" >&2; exit 1; }
echo "sanity checks passed"

echo "== login: 50 usernames x 1000 passwords from 200 addresses, plus one ordinary customer"
docker run --rm --network host --user "$(id -u):$(id -g)" --cpuset-cpus "$k6_cpus" -v "$PWD/test/k6:/scripts:ro" -v "$out:/out" \
  -e "TARGET=http://127.0.0.1:${sherlock_port}" "$image" run --quiet --summary-export "/out/login.json" /scripts/login-stuffing.js \
  > "$out/login.txt" 2>&1 || true

python3 - "$out/login.json" "$per_username" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))["metrics"]
limit = int(sys.argv[2])
def count(name):
    return int(m.get(name, {}).get("count", 0))
reached, refused, unexpected = count("attack_reached"), count("attack_refused"), count("attack_unexpected")
ok = m.get("customer_login_ok", {}).get("value", 0)
budget = 50 * limit + 100  # each account's threshold, plus requests already in flight when it tripped
print(f"guesses that reached the origin: {reached} (budget {budget})")
print(f"guesses refused by Sherlock:    {refused}")
print(f"unexpected answers:             {unexpected}")
print(f"customer logins succeeded:      {ok:.4f} of attempts")
good = reached <= budget and unexpected == 0 and ok == 1 and reached + refused >= 49000
print(f"M11 acceptance 1: {'PASS' if good else 'FAIL'}")
sys.exit(0 if good else 1)
PY
