# Quickstart: run Sherlock from a YAML file

This puts Sherlock in front of a local app using only a config file. There is no database, API or dashboard yet (those arrive in later milestones).

## 1. Build

```sh
make build            # produces bin/sherlock
# or, without the dashboard build:
CGO_ENABLED=0 go build -trimpath -o bin/sherlock ./cmd/sherlock
```

## 2. Write a config

Save as `sherlock.yaml`. This protects an app listening on `127.0.0.1:3000`, first in `detect` mode so nothing is blocked while you look at what would be.

```yaml
schema_version: 1
sites:
  - id: myapp
    name: My app
    hosts: [myapp.localhost]
    tls: { mode: none }          # plain HTTP for local use; see "HTTPS" below
    policy:
      mode: detect               # off | detect | block
    upstreams:
      targets: ["127.0.0.1:3000"]
```

Unknown or misspelled keys are errors, and every error names the path, for example `/sites/0/policy/mod: unknown field "mod"`.

## 3. Run

```sh
./bin/sherlock run --config sherlock.yaml --http-port 8080
```

Ports below 1024 need privileges (or `net.ipv4.ip_unprivileged_port_start=0`), so use `--http-port 8080` while trying it out. The default is 80. Logs are JSON lines on stdout.

## 4. Try an attack

```sh
curl -i --get --data-urlencode "id=1' OR '1'='1" -H 'Host: myapp.localhost' http://127.0.0.1:8080/
```

In `detect` mode the request reaches your app (HTTP 200 from it), and a `decision` log line appears with `"action":"log"` and the CRS rules that matched. The request is a "would have blocked" when rule `949110` is among the findings.

## 5. Turn on blocking

Change `mode: detect` to `mode: block`, then reload without dropping connections:

```sh
kill -HUP "$(pgrep -f 'sherlock run')"
```

The same request now returns `403`. Ask for JSON to get an RFC 9457 problem document with an `event_id`; a browser (`Accept: text/html`) gets an HTML page with the same ID. Quote the ID when investigating a false positive: it matches the `event_id` in the decision log.

If the new file is invalid, Sherlock logs the errors and keeps serving the previous configuration.

## Tuning per path

A policy block can be set globally (`global.defaults`), per site (`policy`) and per endpoint (`endpoints[].policy`). Lower levels win; endpoints are matched most-specific first.

```yaml
global:
  defaults:
    waf: { paranoia_level: 1 }
sites:
  - id: myapp
    hosts: [myapp.localhost]
    tls: { mode: none }
    policy: { mode: block }
    upstreams: { targets: ["127.0.0.1:3000"] }
    endpoints:
      - id: login                       # stricter rules only here
        match: { path: /login, methods: [POST] }
        policy: { waf: { paranoia_level: 2 } }
      - id: health                      # not inspected
        match: { path: /healthz }
        policy: { mode: off }
      - id: uploads                     # larger bodies
        match: { path_prefix: /media }
        policy: { waf: { max_body_bytes: 52428800 } }
```

Match with exactly one of `path`, `path_prefix` or `path_glob` (Go `path.Match` syntax), optionally narrowed by `methods`. Precedence: exact path, then longer prefix or glob, then method-specific over any method. Two endpoints that can match the same request at the same precedence are rejected when the file loads.

## HTTPS

- `tls: { mode: acme }` (the default) obtains certificates automatically. Set `global.acme.email` and make ports 80 and 443 reachable from the internet.
- `tls: { mode: file, cert_file: ..., key_file: ... }` uses your own PEM files.
- `tls: { mode: none }` serves plain HTTP only.

With HTTPS on, port 80 redirects to HTTPS. Requests for a host that is not in the config get `421`.

## Behind a load balancer

```yaml
global:
  trusted_proxies: ["10.0.0.0/8"]
  client_ip_headers: ["X-Forwarded-For"]
```

The client address is the right-most address in the header that is not a trusted proxy. Without `trusted_proxies`, forwarded headers are ignored.

## What is not in this milestone

Rate limits, access lists, bots, response inspection, exclusions and custom rules, the API and the dashboard.

## Try it in containers

`test/e2e-compose/` runs Sherlock in front of httpbin; see the comments at the top of `compose.yaml`.
