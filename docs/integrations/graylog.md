# Graylog

Use the syslog exporter to a Graylog **Syslog TCP** input. Graylog parses the RFC 5424 header; the payload (CEF or JSON) becomes the message.

## Prerequisites

- Graylog with a **Syslog TCP** input (System → Inputs → select "Syslog TCP" → Launch new input). For TLS, set a certificate and private key file readable by Graylog on the server and enable TLS on the input; optionally require client certificates and give a directory of trusted CAs. Graylog's documentation says TCP inputs are the more reliable choice, since each message is acknowledged at the network level, and recommends TLS. **Verify against your Graylog version** the exact option names and whether octet-counting framing is accepted (otherwise set Sherlock's `framing` to `newline`).
- If the certificate is from a private CA, the CA must be trusted by Graylog's Java keystore when you use client authentication.

## Sherlock settings

JSON payload is the easiest to work with in Graylog:

<!-- validate:syslog -->

```json
{
  "network": "tls",
  "address": "graylog.example.internal:12514",
  "format": "json",
  "framing": "newline",
  "tls": { "server_name": "graylog.example.internal" }
}
```

CEF payload (if you use a CEF-aware pipeline or the Illuminate/content pack your edition offers; **verify against your version**):

<!-- validate:syslog -->

```json
{
  "network": "tcp",
  "address": "graylog.example.internal:12514",
  "format": "cef",
  "framing": "newline"
}
```

## Graylog side: turning the JSON payload into fields

The syslog input stores the payload as `message`. Parse it with a pipeline rule (the `parse_json` function) or a JSON extractor on the input. A pipeline rule sketch (**verify the syntax against your version**):

```
rule "sherlock event json"
when
  has_field("message") && starts_with(to_string($message.message), "{")
then
  let doc = parse_json(to_string($message.message));
  set_fields(to_map(doc), "sherlock_");
end
```

Fields then include `sherlock_id` (use it as the deduplication key), `sherlock_site_id`, `sherlock_action`, `sherlock_client`, and so on, following [events.md](../architecture/events.md).

## Verify

1. **Test** button; a message "Sherlock exporter connectivity test" with application name `sherlock` appears under Search.
2. Trigger an event and search `application_name:sherlock`.
3. In Graylog, the input's "Network IO" shows traffic; in Sherlock `sherlock_exporter_sent_total` rises.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Test fails at TLS | certificate chain, `server_name`, `tls.ca_pem`; client-auth CA directory |
| Messages arrive as one long line or are truncated | framing mismatch: switch between `octet` and `newline` |
| Message text starts with a number and a space | the input treated octet counting as part of the message: use `newline` framing |
| `pending` grows | Graylog input stopped or back-pressured; check `sherlock_exporter_send_failures_total` |
| Fields missing | the pipeline rule is not attached to the stream, or the message is CEF not JSON |

## Security notes

Syslog has no authentication; restrict the input to Sherlock's address and use TLS across networks. A webhook exporter into a Graylog HTTP input is possible but Graylog cannot verify the HMAC; prefer syslog.
