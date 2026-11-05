# Protect your first site

This takes a running node ([install](install.md)) and puts one website behind it, in **detect** mode: attacks are recorded, nothing is blocked. You switch to blocking later ([detect to block](detect-to-block.md)).

You need: the hostname your users visit (for example `app.example.com`), pointing at this machine in DNS; the address of the real application (the upstream), for example `10.0.0.12:8080`; and ports 80 and 443 reachable from your users (and from the internet if you want a Let's Encrypt certificate).

## 1. Sign in

Open the control plane (`https://127.0.0.1:9443` by default), sign in as the administrator you created and enrol your authenticator app.

## 2. Check the upstream

Before adding the site, confirm the node can reach the application. Link-local addresses (cloud metadata, `169.254.0.0/16`) are always refused; private addresses are fine.

```sh
curl -sk -X POST https://127.0.0.1:9443/api/v1/system/test-upstream \
  -H "Authorization: Bearer $SHERLOCK_TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"10.0.0.12:8080"}'
# {"reachable":true,"status":200,"latency_ms":3}
```

Create a token with `sherlock token create --user ada --name setup --scope write --expires-in 24h`. The secret is printed once.

## 3. Add the site

Either in the dashboard (Sites, add a site) or with a YAML file. The YAML route is what you will want in version control:

```yaml
# sherlock.yaml
schema_version: 1
sites:
  - id: app
    name: Application
    hosts: [app.example.com]
    tls: { mode: acme }              # Let's Encrypt; use `none` for plain HTTP while testing
    upstreams:
      targets: ["10.0.0.12:8080"]
    policy:
      mode: detect                   # off | detect | block
```

```sh
sherlock config validate sherlock.yaml                 # offline; errors name the exact path
sherlock config import sherlock.yaml                   # a fresh node: stored and activated
# on a node that already has a configuration:
sherlock config apply sherlock.yaml --server https://127.0.0.1:9443 --token "$SHERLOCK_TOKEN" --tls-pin <tls_spki_sha256>
```

A change is applied atomically: if the new configuration cannot be activated, the previous one stays live.

## 4. Point traffic at Sherlock

Make `app.example.com` resolve to this machine. With `tls.mode: acme` the first HTTPS request triggers certificate issuance (ports 80 and 443 must be reachable from the internet; the dashboard shows the certificate state). To bring your own certificate, upload it and reference it with `tls: { mode: file, cert_id: <id> }`.

## 5. Check it

```sh
curl -sI https://app.example.com/                        # your application's response
curl -s  "https://app.example.com/?q=<script>alert(1)</script>" -o /dev/null -w '%{http_code}\n'
```

In detect mode the second request still reaches your application (status unchanged), and an event appears in the dashboard's event list with the matched rules and an anomaly score. If nothing shows up, check `/readyz`, DNS, and the node's journal.

## Where next

- Let it run for a week or two with real traffic, then follow [detect to block](detect-to-block.md).
- Restrict who may reach the site or the admin paths: [access control](access-control.md).
- Set up [backups](backup-restore.md) before you depend on the node.
