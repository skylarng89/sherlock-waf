#!/usr/bin/env bash
# Smoke test for the compose test bed. Expects `make e2e-up` to have run.
set -euo pipefail

port=${SHERLOCK_HTTP_PORT:-18080}
admin=${SHERLOCK_ADMIN_PORT:-19443}
fail=0

check() { # description expected actual
  if [[ "$2" == "$3" ]]; then echo "ok   $1 ($3)"; else echo "FAIL $1: want $2 got $3"; fail=1; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }

for _ in $(seq 1 60); do
  [[ "$(code "http://127.0.0.1:${admin}/readyz")" == 200 ]] && break
  sleep 1
done
# Juice Shop needs a while to boot; wait until it answers through Sherlock.
for _ in $(seq 1 90); do
  [[ "$(code "http://juice.localhost:${port}/")" == 200 ]] && break
  sleep 2
done
check "readyz" 200 "$(code "http://127.0.0.1:${admin}/readyz")"
check "healthz" 200 "$(code "http://127.0.0.1:${admin}/healthz")"

check "juice shop home through sherlock" 200 "$(code "http://juice.localhost:${port}/")"
check "benign search" 200 "$(code "http://juice.localhost:${port}/rest/products/search?q=apple")"
check "sqli blocked" 403 "$(code --get --data-urlencode "q=' OR 1=1--" "http://juice.localhost:${port}/rest/products/search")"
check "xss blocked" 403 "$(code --get --data-urlencode "q=<script>alert(1)</script>" "http://juice.localhost:${port}/rest/products/search")"
check "block mode httpbin" 403 "$(code --get --data-urlencode "id=1' OR '1'='1" "http://site.localhost:${port}/get")"
check "detect mode httpbin proxies" 200 "$(code --get --data-urlencode "id=1' OR '1'='1" "http://detect.localhost:${port}/get")"
check "unknown host" 421 "$(code -H 'Host: unknown.localhost' "http://127.0.0.1:${port}/")"

body=$(curl -s --max-time 20 -H 'Accept: application/json' --get --data-urlencode "id=1' OR '1'='1" "http://site.localhost:${port}/get")
[[ "$body" == *'"event_id"'* ]] && echo "ok   problem+json carries event_id" || { echo "FAIL no event_id in: $body"; fail=1; }

metrics=$(curl -s --max-time 10 "http://127.0.0.1:${admin}/metrics")
[[ "$metrics" == *'sherlock_requests_total{action="block",site="juice"}'* ]] && echo "ok   metrics count blocks" || { echo "FAIL metrics missing block counter"; fail=1; }

exit "$fail"
