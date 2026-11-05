# Integrations: SIEM export and alerting

Sherlock ships its security events and its audit log to your SOC, and tells people when something needs attention. Everything here is configured in the dashboard (Integrations → Exporters, Notification channels, Alerts) or through the API (`/exporters`, `/notification-channels`, `/alert-rules`; see [api.md](../architecture/api.md)).

| Guide | Destination |
| --- | --- |
| [splunk.md](splunk.md) | Splunk (syslog/CEF) |
| [elastic.md](elastic.md) | Elastic (OTLP) |
| [sentinel.md](sentinel.md) | Microsoft Sentinel (syslog/CEF through the Azure Monitor Agent) |
| [graylog.md](graylog.md) | Graylog (syslog) |
| [wazuh.md](wazuh.md) | Wazuh (remote syslog) |
| [webhook-signature.md](webhook-signature.md) | Verifying the webhook exporter's HMAC signature |
| [alerts.md](alerts.md) | Alert rules and notification channels |

## Concepts

**Exporter types** built into the open-source core: `syslog` (RFC 5424 over UDP, TCP or TLS, payload CEF or JSON), `webhook` (HTTPS JSON batches signed with HMAC-SHA256) and `otlp` (OpenTelemetry logs over OTLP/HTTP JSON or OTLP/gRPC). Enterprise adds vendor-specific types through the same extension point ([extension-points.md](../architecture/extension-points.md)).

**Streams.** Every exporter has a `stream`: `events` (security events, schema `sherlock.event.v1`), `audit` (the hash-chained audit log, schema `sherlock.audit.v1`) or `both`. Use a separate exporter per stream when the SIEM wants them in different indexes.

**Delivery is at-least-once.** A record leaves the exporter's spool only after the destination accepted its batch. If Sherlock stops between the acceptance and the cursor write, or a destination accepts a batch but the answer is lost, the batch is sent again. Receivers must deduplicate on the record id:

| Exporter | Where the id is |
| --- | --- |
| `webhook` | `records[].id` |
| `syslog` (CEF) | `cs2` (`cs2Label=event_id` for events, `audit_id` for audit) |
| `syslog` (JSON) | `id` in the payload |
| `otlp` | attribute `sherlock.event.id` (events) |

Order is preserved per exporter in normal operation, but a retry after a failure can arrive after newer batches have started; use the timestamp, not arrival order.

**What an exporter does.** Each exporter has its own bus subscription, its own bounded disk spool under `<data dir>/exporters/<id>/` (directory mode 0700, files 0600), and its own sender. A dead or slow destination fills only its own spool; the data plane, the event store and the other exporters are unaffected. Batches hold up to 500 records or 1 MiB, each attempt has a 10 s timeout, and failures retry with exponential backoff and jitter from 1 s up to 60 s. A reply that retrying cannot fix (HTTP 4xx other than 408 and 429, gRPC `INVALID_ARGUMENT`, `UNAUTHENTICATED`, ...) discards that batch and counts it as `rejected`, so one bad batch cannot block the queue.

An exporter ships what happens after it starts. It does not replay history; use the event store or a backup for that.

## Sizing the spool for an outage

The spool holds at most 256 MiB per exporter (currently fixed; it is not configurable in the API). When it is full, the oldest 4 MiB segment is deleted and its unsent records are counted in `sherlock_exporter_dropped_total{reason="spool_full"}`.

```
bytes per record  ≈ average event JSON size + 110   (envelope and framing)
outage you survive = 256 MiB / (events per second × bytes per record)
```

Worked example: events average 2 KB (one finding, a few headers), the site averages 200 events per second during an attack. Bytes per record ≈ 2,158. 256 MiB = 268,435,456 bytes. 268,435,456 / (200 × 2,158) ≈ 622 s, about 10 minutes. At 20 events per second the same spool lasts about 100 minutes. Measure your own average with `sherlock_exporter_spool_bytes / sherlock_exporter_pending`. Keep free disk space for every exporter at once: `exporters × 256 MiB`. Sherlock never uses more than that for spools.

## Network and TLS rules

- Outbound connections from the `webhook`, `otlp` and notification senders refuse link-local and unspecified addresses (including the cloud metadata address 169.254.169.254) at connect time, after DNS resolution, so rebinding does not help. Loopback and private ranges are allowed, because SIEMs are usually internal.
- Redirects are never followed.
- `webhook` and `otlp` require `https://` unless the setting `allow_http` is `true` (use it only on a trusted network).
- TLS 1.2 or newer, certificate verification always on. There is no "skip verify" option. For a private CA, set `tls.ca_pem`.
- Syslog over UDP and plain TCP are unencrypted; use `network: "tls"` across anything but a trusted segment.
- URLs, tokens, HMAC secrets and custom headers are stored encrypted with the node key and shown as `********` in the dashboard and API. Sending `********` back keeps the stored value.

## Test button

Every exporter and channel dialog has a **Test** button (`POST /exporters/test`, `POST /notification-channels/test`). It builds the sender from the form and checks the destination without saving anything and without the exporter being enabled:

| Type | What the test sends |
| --- | --- |
| `syslog` | one RFC 5424 message with MSGID `test` and the text "Sherlock exporter connectivity test" |
| `webhook` | a signed POST with an empty batch and `"test": true` (exercises DNS, TLS, the signature and the receiver's auth) |
| `otlp` | one INFO log record "Sherlock exporter connectivity test" with attribute `sherlock.stream=test` |
| notification channels | a clearly labelled test message |

A failure shows a short reason without credentials. UDP syslog cannot report delivery, so a passing UDP test only proves the datagram was sent. When you edit a saved exporter, fields still showing `********` keep their stored secrets during the test.

## Metrics to alert on

| Metric | Meaning | Alert when |
| --- | --- | --- |
| `sherlock_exporter_pending` | records spooled, not delivered | grows for more than a few minutes |
| `sherlock_exporter_spool_bytes` | spool size on disk | above 50% of 256 MiB |
| `sherlock_exporter_send_failures_total` | failed delivery attempts | rate above 0 for 5 minutes |
| `sherlock_exporter_dropped_total{reason}` | records that will never be delivered | any increase (`spool_full`, `lagged`, `rejected`) |
| `sherlock_exporter_last_success_timestamp_seconds` | last accepted batch | older than 5 minutes while events flow |
| `sherlock_events_dropped_total` | events lost on the bus before any consumer read them | any increase (also available as the built-in alert kind `events_dropped`) |

`sherlock_exporter_sent_total` is the delivered counter. All series carry the labels `exporter` (the id) and `type`.
