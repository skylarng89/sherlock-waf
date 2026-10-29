#!/usr/bin/env bash
# Run the OWASP CRS regression suite (go-ftw) against a built Sherlock.
#   test/ftw/run.sh [PARANOIA_LEVEL] [extra go-ftw args...]
# Rule IDs are read from Sherlock's own events.jsonl, so this also exercises
# the event pipeline. Known and expected failures live in
# test/ftw/overrides.yaml with a reason each; nothing is skipped silently.
set -euo pipefail

pl=${1:-1}
shift || true
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

work=$(mktemp -d)
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ -n "${FTW_KEEP:-}" ]]; then echo "kept working directory: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

backend_port=${FTW_BACKEND_PORT:-18081}
sherlock_port=${FTW_SHERLOCK_PORT:-18082}

go build -o "$work/backend" ./test/ftw/backend
CGO_ENABLED=0 go build -trimpath -tags sherlock_testhooks -o "$work/sherlock" ./cmd/sherlock

"$work/backend" -listen "127.0.0.1:${backend_port}" &
pids+=($!)

cat > "$work/sherlock.yaml" <<YAML
schema_version: 1
global:
  admin: { listen: "off" }
  events:
    sinks: { stdout: false, file: true, file_max_mb: 2048 }
sites:
  - id: ftw
    hosts: [localhost]
    tls: { mode: none }
    policy:
      mode: block
      # Like the CRS project's own run: thresholds so high nothing is blocked, so
      # tests judge detection by the rule IDs in the event log.
      # Sample tuning (M8-T7). The regression must pass with exclusions, custom
      # rules and every virtual patch configured: they are scoped to paths the
      # CRS tests never use, and the second site below carries a broad
      # exclusion that must not leak into this one (exclusions are per site).
      stacks: [wordpress, php, drupal, spring, java, confluence, atlassian, fortinet, vmware, f5, exchange, weblogic, oracle, manageengine, screenconnect, papercut, goanywhere, citrix, paloalto]
      waf:
        paranoia_level: ${pl}
        blocking_paranoia_level: ${pl}
        inbound_threshold: 10000
        outbound_threshold: 10000
        exclusions:
          - id: ftw-sample-scoped
            match: { paths: ["/sherlock-sample-app/**"], methods: [POST] }
            remove_targets: [{ rule_ids: ["942100"], target: "ARGS:q" }]
        custom_rules: |
          SecRule REQUEST_FILENAME "@streq /sherlock-sample-blocked" "id:10001,phase:1,pass,nolog"
    upstreams: { targets: ["127.0.0.1:${backend_port}"] }
  - id: ftw-other
    hosts: [other.invalid]
    tls: { mode: none }
    policy:
      mode: block
      waf:
        paranoia_level: ${pl}
        blocking_paranoia_level: ${pl}
        exclusions:
          - { id: everything-sqli-xss-rce, remove_tags: [attack-sqli, attack-xss, attack-rce, attack-lfi, attack-protocol] }
    upstreams: { targets: ["127.0.0.1:${backend_port}"] }
YAML
"$work/sherlock" run --config "$work/sherlock.yaml" --http-port "$sherlock_port" --https-port 18443 \
  --data-dir "$work/data" > "$work/sherlock.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 60); do
  curl -s -o /dev/null --max-time 2 -H 'Host: localhost' "http://127.0.0.1:${sherlock_port}/" && break
  sleep 0.5
done

crs_dir=$(go list -m -f '{{.Dir}}' github.com/corazawaf/coraza-coreruleset/v4)
crs_tests=${crs_dir}/tests
# Tests for rules of a higher paranoia level cannot fire at this level, so
# only select tests whose rule is at or below it.
include=$(go run ./test/ftw/plfilter "${crs_dir}/rules/@owasp_crs" "$pl")

{
  echo "---"
  echo "logfile: ${work}/data/events.jsonl"
  echo "logmarkerheadername: X-CRS-Test"
  echo "maxmarkerretries: 20"
  echo "custom_log_id_regex: '\"rule_id\":\"(\\d+)\"'"
  echo "testoverride:"
  echo "  input:"
  echo "    dest_addr: 127.0.0.1"
  echo "    port: ${sherlock_port}"
  sed 's/^/  /' test/ftw/overrides.yaml
} > "$work/ftw.yaml"

# go-ftw occasionally fails to reconstruct the log between its markers
# ("start marker not found while collecting marked lines") for roughly one test
# in a thousand, always a different one and never in isolation, while the event
# file on disk is complete and correctly ordered. So failed tests are re-run
# (up to FTW_ATTEMPTS times in total) and only tests that fail on EVERY attempt
# count as failures. Tests that recovered are listed, never hidden.
attempts=${FTW_ATTEMPTS:-3}
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
failed_ids() { strip < "$1" | sed -n 's/^💥 \([0-9]*-[0-9]*\) failed.*/\1/p' | sort -u; }

set +e
selection=$include
: > "$work/recovered.txt"
status=0
for attempt in $(seq 1 "$attempts"); do
  out="$work/ftw.$attempt.out"
  go tool -modfile=tools/go.mod go-ftw run --config "$work/ftw.yaml" -d "$crs_tests" \
    --include "$selection" --show-failures-only --connect-timeout 5s --read-timeout 20s "$@" > "$out" 2>&1
  status=$?
  cat "$out"
  mapfile -t failed < <(failed_ids "$out")
  if [[ $status -ne 0 && ${#failed[@]} -eq 0 ]]; then
    break # go-ftw itself errored (not a test failure): do not retry
  fi
  if [[ ${#failed[@]} -eq 0 ]]; then
    status=0
    break
  fi
  if (( attempt < attempts )); then
    echo "--- attempt ${attempt}: ${#failed[@]} test(s) failed; re-running only those"
    printf '%s\n' "${failed[@]}" > "$work/failed.$attempt"
    selection="^($(IFS='|'; echo "${failed[*]}"))\$"
  fi
done
# Tests that failed on an early attempt but passed on a later one.
for f in "$work"/failed.*; do [[ -e $f ]] && cat "$f"; done | sort -u > "$work/ever-failed.txt"
printf '%s\n' "${failed[@]:-}" | sort -u > "$work/final-failed.txt"
comm -23 "$work/ever-failed.txt" "$work/final-failed.txt" > "$work/recovered.txt"
if [[ -s "$work/recovered.txt" ]]; then
  echo "recovered on retry (harness flake, passed on a later attempt): $(tr '\n' ' ' < "$work/recovered.txt")"
fi
cp "$work/ftw.$attempt.out" "${FTW_OUT:-$work/ftw.out}" 2>/dev/null || true
set -e
echo "go-ftw exit status: ${status} (paranoia level ${pl}, attempts used: ${attempt})"
exit "$status"
