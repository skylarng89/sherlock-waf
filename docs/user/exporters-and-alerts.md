# Exporters, notification channels and alerts

Three dashboard pages under the sidebar entries **Exporters**, **Channels** and **Alerts** send Sherlock's data to your SOC and tell people when something needs attention. Everyone with read access can look at them; changing anything needs write access (the `config:write` permission, held by the administrator role). Viewers see the pages read-only.

## Exporters

An exporter ships records to an external system. Delivery is **at-least-once**: a record can arrive twice after a crash or timeout, so receivers should deduplicate on the record `id`. While the destination is down, records wait in a disk spool; when the spool is full the oldest are dropped and counted.

Each exporter has a **stream**: security *events*, the *audit log*, or both.

| Type | Settings |
| --- | --- |
| `syslog` | Transport (UDP, TCP or TLS), address, payload format (CEF or JSON), facility, application name, framing (octet counting or newline), TLS server name and CA certificate |
| `webhook` | URL, signing secret (at least 32 characters), extra headers, plain-HTTP switch. Requests carry an HMAC-SHA256 signature header |
| `otlp` | Endpoint, protocol (HTTP or gRPC), extra headers, CA certificate |

Extension types (for example Splunk HEC in the Enterprise edition) appear in the **Type** list automatically. They have no form, so their settings are edited as JSON.

The table shows live delivery state, refreshed every 15 seconds while the page is visible:

- **Sent**: records the destination accepted.
- **Pending**: records waiting in the spool.
- **Dropped**: records that will never be delivered (spool full, the in-memory buffer overrun, or the destination refused them). Anything above zero deserves a look.
- **Spool**: bytes held on disk.
- **Last delivery** and the **last error**, with how long ago each happened.

**Test** sends a connectivity check without saving anything. In the edit dialog it uses the values in the form; masked values are filled in from the saved exporter. The result is announced to screen readers.

## Notification channels

A channel is where an alert is delivered: email (SMTP), a generic webhook, a Slack-compatible webhook, or Microsoft Teams. **Test** sends a clearly labelled test message.

A channel that an alert rule still uses cannot be deleted; the error names the rules.

## Alerts

A rule watches one condition and notifies one or more channels:

| Condition | Settings | Fires when |
| --- | --- | --- |
| Blocks above a threshold | Site (optional), threshold, window | Blocks in the window exceed the threshold |
| New attacking country | Site (optional), window, baseline | A country appears in the window that was absent from the baseline before it |
| Certificate expiring | Days | A certificate expires in fewer days than this |
| Feed failure | none | A threat feed is failing |
| Events dropped | none | The event buffer dropped events since the last check |
| Upstream unhealthy | Site (optional) | An upstream's last health probe failed |

Rules are checked every 30 seconds. After a rule fires, it does not notify again for the same subject during its **cool-down** (60 seconds to 7 days, 15 minutes by default). The table shows whether each rule is firing, when it was last checked and last fired, how many repeats the cool-down held back, and any error. Alert state is kept in memory, so a condition that is still true after a restart notifies once more.

## Secrets

Webhook URLs, signing secrets, passwords, tokens and custom header values are secrets. They are stored encrypted, and the dashboard and API show them as `********`. When you edit an object, leave a secret field empty (its placeholder reads *unchanged*) to keep the stored value, or type a new one to replace it. For headers, a value that still reads `********` is kept.
