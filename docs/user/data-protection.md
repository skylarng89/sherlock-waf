# Data protection (response scanning)

Data protection looks at what your application sends back and stops card numbers, IBANs and other values you name from leaving in clear. It is one of the finance protections (with login protection), and it is off until you turn it on.

In `detect` mode a match is only recorded and the response is never changed; switch the site to `block` to enforce (see [From detect to block](detect-to-block.md)).

## Turn it on

```yaml
sites:
  - id: bank
    hosts: [bank.example.com]
    policy:
      mode: block
      dlp:
        enabled: true
        detect: [pan, iban, "custom:national_id"]
        custom_patterns:
          - { name: national_id, pattern: "[A-Z]{2}[0-9]{6}[A-D]" }
        action: mask            # mask | block | log
```

The same block works at the global defaults, the site and an endpoint, like every policy block. `detect` and `custom_patterns` are lists: a lower level replaces the list of the level above. In the dashboard it is the site's **Data protection** tab.

## What is detected

| Detector | Finds | Notes |
| --- | --- | --- |
| `pan` | Payment card numbers: 13 to 19 digits that pass the Luhn check, written together or in the usual groups with single spaces or dashes (`4111 1111 1111 1111`, `3782 822463 10005`). | A number glued to letters or to more digits is treated as part of an identifier and left alone, so order numbers, UUID fragments and hashes are not masked. A random digit string passes the Luhn check one time in ten; this rule is what keeps ordinary identifiers intact. |
| `iban` | International bank account numbers of every country in the IBAN registry, with the right length for the country and a valid ISO 13616 check, optionally written in groups of four (`DE89 3704 0044 0532 0130 00`). | Upper-case only. |
| `custom:<name>` | Whatever your own pattern matches. | See below. |

When two detectors match the same text, the one that starts first wins, so a value is reported once.

## What happens to a match

| `action` | Response to the client |
| --- | --- |
| `mask` (default) | The value is overwritten in place and the response is delivered. |
| `block` | The whole response is replaced by the block page (status 502) before a single byte of the original is sent. |
| `log` | The response is delivered unchanged; the finding is recorded. |

Masking never changes the length of the response, so `Content-Length` and the layout around the value stay correct:

- **Card numbers**: every digit but the last four becomes `*`, separators stay: `**** **** **** 1111`. An unquoted JSON number (`{"n": 4111111111111111}`) keeps digits so the document stays valid JSON: `9999999999991111`.
- **IBANs**: the country code and the last four characters stay, the rest becomes `*`: `GB****************5432`. The check digits are masked too.
- **Custom matches**: fully masked. Letters, digits and every byte of a multi-byte character become `*`; other ASCII (dashes, dots) stays.

In `detect` mode, and with `action: log`, nothing is changed. The finding says which it was.

## Which responses are scanned

- A response is scanned when its media type is on the allow-list `content_types` (default `text/html`, `text/plain`, `application/json`, `application/xml`, `text/xml`; an entry matches by prefix, so `text/` covers every text type, and `application/json` also covers `application/problem+json`). Images, downloads and event streams (`text/event-stream`) are never held back. A response with no `Content-Type` at all is passed unscanned and counted (`sherlock_dlp_skipped_total{reason="content_type_unknown"}`).
- Error responses (4xx, 5xx) are scanned too: error pages are a common place for a card number to leak. `HEAD` requests, `204` and `304` have no body and are skipped. WebSocket upgrades are not touched.
- **Size limit.** The response is held back until it ends or reaches `max_body_bytes` (default 1 MiB, up to 16 MiB), scanned, then sent. A value that straddles several chunks is found. If the response is larger than the limit, the part already held is still masked (or blocked), and **the rest streams through unscanned**; it is counted (`reason="too_large"`). Raise the limit if your pages are larger, or list the large download types out of `content_types`.
- **Compression.** Sherlock can read identity and gzip bodies. It asks your application for gzip when the client accepts gzip and for no compression otherwise, so a client that prefers `br` or `zstd` is sent a gzip or plain response instead. A gzip body is decoded (never beyond the size limit, so a decompression bomb costs no more than a plain body), masked and encoded again with a correct `Content-Length`; a body without matches is sent byte for byte. A response that arrives with another encoding anyway is passed unscanned and counted (`reason="encoding"`).

## Custom patterns

Patterns use Go's RE2 syntax, so a pattern cannot make scanning slow whatever a response contains. There is no lookahead or back-reference. A pattern must not match the empty string, a name is lower-case letters, digits and underscores (at most 32), a pattern is at most 512 characters, and a level can declare 20. Anchor patterns with `\b` so they do not match inside longer words.

## What is recorded, and what never is

Each response with matches produces one finding per detector (`module: dlp`, `rule_id: pan`, `iban` or `custom:<name>`, target `RESPONSE_BODY`) with a message that holds counts only: `2 card numbers found in the response (masked)`. **The matched values are never written to events, logs, the audit trail, exports, error messages or metrics labels**, including for custom patterns. Metrics:

- `sherlock_dlp_matches_total{site,detector,action}`: values found (detector is `pan`, `iban` or `custom`).
- `sherlock_dlp_skipped_total{site,reason}`: responses passed unscanned (`too_large`, `encoding`, `content_type_unknown`).

If the scanner itself fails (a bug, not a data condition), the failure is counted in `sherlock_internal_errors_total`; in `block` mode the response is withheld rather than sent unscanned, in `detect` mode it is passed on.

## Limits: what this does not do

- It is a safety net on the way out, **not a way to take your application out of PCI DSS scope**. Card data that reaches Sherlock has already left your application's boundary. Fix the leak at its source as well.
- It reads text. Card numbers inside images, PDFs, archives or encoded fields (base64, URL-encoded) are not found.
- A card number split by anything other than a single space or dash (`4111.1111.1111.1111`, line breaks, HTML tags between groups) is not found.
- Responses beyond `max_body_bytes` are only checked up to the limit, as described above.
- Masking the response does not change what the origin logs or stores.
- Request bodies are not scanned; request-side card numbers are already masked in Sherlock's own events.
