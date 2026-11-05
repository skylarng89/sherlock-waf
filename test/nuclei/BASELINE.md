# Juice Shop attack-replay baseline

Recorded 2026-10-28 on a developer machine. **Sherlock** built from this
repository, paranoia level 1, block mode, CRS 4.25.0, default thresholds
(inbound 5), against **OWASP Juice Shop v19.0.0** (`test/e2e-compose`). Scanners
reach Sherlock by hostname (`juice.localhost`), as a browser would.

Three independent measurements, because each answers a different question:

| Tool | Question | Result |
| --- | --- | --- |
| Juice Shop challenge replay (`test/juice/challenges.py`) | Which documented injection payloads does Sherlock stop? | **23 / 29** blocked |
| nuclei DAST fuzzing (`test/nuclei/run.sh`) | What does a generic scanner manage to exploit, with and without Sherlock? | 1 exploitable, 0 stopped (the one finding is a lone quote, below) |
| ZAP baseline (`test/zap/run.sh`) | Does Sherlock break or hide normal browsing? | Same 95 URLs and same alerts both ways |

## 1. Injection challenge replay (acceptance criterion 3)

Every payload is sent directly to Juice Shop and through Sherlock. "Blocked"
means HTTP 403 carrying an `X-Sherlock-Event-Id`.

| Category | Blocked at PL1 |
| --- | --- |
| SQL injection | 5 / 6 |
| NoSQL injection | 3 / 3 |
| Cross-site scripting | 6 / 6 |
| Code injection (RCE, SSTI, shell metacharacters) | 4 / 5 |
| XML external entity | **0 / 2** |
| Path traversal / local file inclusion | 3 / 4 |
| Server-side request forgery | 2 / 2 |
| Open redirect | **0 / 1** |
| **Total** | **23 / 29 (79%)** |

### Known gaps at PL1

Kept in `test/juice/known-gaps.txt`; the replay exits non-zero if a payload *not*
listed there stops being blocked, and prints a notice when a listed one starts
being blocked.

| Payload | Why it passes |
| --- | --- |
| Bare single quote in the product search | A lone quote scores below the PL1 threshold of 5. Juice Shop answers 500 with an SQL error: information disclosure, not a working injection. Real injections are blocked. (This is the one nuclei finding.) |
| B2B `orderLinesData` ReDoS | A JavaScript regular-expression string in a JSON value matches no PL1 rule. The endpoint needs a login. |
| XXE: entity in a multipart file part | XML inside a file part is not parsed as XML by the WAF. (Juice Shop v19 answers 410.) |
| XXE: XML body with an external DTD | CRS has no PL1 rule for external-DTD declarations. |
| Poison null byte on `/ftp` | `%2500` decodes once to a literal `%00`, not a NUL byte. The attack relies on a second decode in the application. |
| Open redirect allow-list bypass | A logic flaw with no signature; CRS does not detect open redirects. |

Raising the paranoia level is expected to close some of these (the bare quote
and, possibly, XXE); that is a measurement for M8 (tuning), not part of this
baseline.

## 2. nuclei

nuclei v3.11.1 with the public template set, **DAST mode** against ten
parameterised Juice Shop endpoints (`targets.txt`), template tags
`sqli,xss,rce,lfi,ssrf,cmdi,ssti,injection,redirect`.

- Exploitable directly: **1** (`sqli-error-based`, the lone quote above).
- Still found through Sherlock: **1**. Stopped: **0 / 1**.

Why so few: nuclei's tag-based templates (the usual `-tags sqli,xss,...`) are
mostly product-specific CVE checks, and a plain scan of Juice Shop's root URL
finds only one informational item (`addeventlistener-detect`) both directly and
through Sherlock. The generic fuzzers only run in DAST mode against URLs that
carry parameters, and Juice Shop is a single-page application with few of them.
For breadth, the replay in section 1 is the more informative measure.

## 3. ZAP baseline

ZAP 2.17.0 `zap-baseline.py` (spider plus passive rules; it does not attack),
one minute.

| | Directly | Through Sherlock |
| --- | --- | --- |
| URLs found | 95 | 95 |
| Alert types | High 1, Medium 2, Low 6, Informational 4 | identical |

No false-positive blocking of normal browsing. Spider coverage is time-boxed,
so small differences between runs are possible.

## Methodology notes (read before comparing numbers)

- **Use hostnames, not IPs.** Scanning `http://127.0.0.1:…` sends a numeric-IP
  `Host` header, which trips CRS rule 920350 (+3 anomaly points) on every
  request; any second minor hit then crosses the threshold. An early run did
  this and the ZAP spider found 3 URLs instead of 95. The scripts now use
  `juice.localhost`.
- Results depend on template and ZAP versions; re-record when they change.
- Juice Shop is deliberately vulnerable and is bound to `127.0.0.1` only for
  the direct measurements.

## Re-running

```sh
make e2e-up
python3 test/juice/challenges.py
test/nuclei/run.sh
test/zap/run.sh
make e2e-down
```
