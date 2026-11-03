# Splunk

Use the syslog exporter with CEF payloads. Sherlock's own `webhook` format is not the Splunk HTTP Event Collector (HEC) format; a native HEC exporter is an Enterprise exporter type ([extension-points.md](../architecture/extension-points.md)). Until then, syslog/CEF is the supported path.

## Prerequisites

- A Splunk instance or heavy forwarder that can receive syslog, or [Splunk Connect for Syslog (SC4S)](https://splunk.github.io/splunk-connect-for-syslog/main/). Splunk recommends SC4S as the syslog receiver in front of indexers; direct inputs work for small setups. **Verify against your version** which route Splunk currently recommends and which ports SC4S listens on by default.
- A receiver reachable from the Sherlock node on a TCP port (TLS recommended).
- The Splunk app or add-on that parses CEF in your environment (for example the Common Information Model-compatible CEF add-on); **verify against your version** the exact sourcetype it expects. Sherlock's CEF vendor/product fields are `Sherlock` / `Sherlock WAF`.

## Sherlock settings

Plain TCP to a Splunk network input, CEF payload:

<!-- validate:syslog -->

```json
{
  "network": "tcp",
  "address": "splunk-hf.example.internal:5514",
  "format": "cef",
  "app_name": "sherlock",
  "facility": 16
}
```

TLS (recommended; set `ca_pem` when Splunk's certificate is from a private CA):

<!-- validate:syslog -->

```json
{
  "network": "tls",
  "address": "splunk-hf.example.internal:6514",
  "format": "cef",
  "tls": {
    "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
    "server_name": "splunk-hf.example.internal"
  }
}
```

Create the exporter with stream `events` (and a second exporter with stream `audit` if the SOC wants the audit log, ideally to a separate index).

Messages are RFC 5424 with octet-counting framing (RFC 6587). If the receiver cannot parse octet counting, set `"framing": "newline"`.

## Splunk side

Direct input (conceptual `inputs.conf` on the receiving forwarder; **verify against your version** and your add-on's documentation):

```
[tcp://5514]
sourcetype = <the sourcetype your CEF add-on expects>
index = sherlock
connection_host = ip

[tcp-ssl:6514]
sourcetype = <same>
index = sherlock

[SSL]
serverCert = /opt/splunk/etc/auth/sherlock/server.pem
sslPassword = <password>
requireClientCert = false
```

With SC4S, add the Sherlock host or a dedicated port to the SC4S context according to the SC4S documentation, and let SC4S assign the sourcetype and index. Because the message is RFC 5424 with a CEF body, check that your parser strips the syslog header before it applies the CEF extraction.

## Verify

1. In Sherlock: Integrations → Exporters → the exporter's **Test** button. The receiver must show a message with `Sherlock exporter connectivity test`.
2. Generate a real event (send a request that triggers a rule on a site in detect mode) and search `index=sherlock "CEF:0|Sherlock|Sherlock WAF"`.
3. Check `sherlock_exporter_sent_total` increases and `sherlock_exporter_pending` returns to 0.

CEF fields: `src` client IP, `requestMethod`, `request` (host + path), `act` action, `rt` request time (ms since epoch), `dvchost` Sherlock node, and labelled `cs1` site, `cs2` event_id, `cn1` anomaly_score. See the mapping in [events.md](../architecture/events.md).

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Test fails with a connection or TLS error | firewall; `server_name` matches the certificate; private CA in `tls.ca_pem` |
| Test passes but no events | `sherlock_exporter_sent_total`; the exporter's stream; the site produced events (detect mode logs findings) |
| `sherlock_exporter_pending` keeps growing | `sherlock_exporter_send_failures_total` and the exporter's last error in the dashboard; receiver down or slow |
| Duplicate events | expected after a retry; deduplicate on `cs2` (event id) |
| One event split across lines | receiver does not understand octet counting; set `framing` to `newline` |
| Fields not extracted | the CEF add-on or parser is not applied to this sourcetype/port |

## Security notes

Use `network: "tls"` outside a trusted segment. Syslog has no authentication: restrict the receiver to the Sherlock node's address. For mutual TLS, set `tls.client_cert_pem` and `tls.client_key_pem` (both, or neither) and require client certificates on the receiver.
