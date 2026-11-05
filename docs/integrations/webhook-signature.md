# Verifying webhook signatures

The `webhook` exporter signs every request. Verify the signature before trusting or parsing the body.

## Request

`POST` to your URL with `Content-Type: application/json` and these headers:

| Header | Value |
| --- | --- |
| `X-Sherlock-Timestamp` | Unix time in seconds when the request was signed |
| `X-Sherlock-Signature` | `sha256=` followed by the lowercase hex HMAC-SHA256 |
| `X-Sherlock-Delivery` | Random id, new for every HTTP attempt |
| `User-Agent` | `Sherlock-WAF/<version>` style product string |

The HMAC key is the exporter's `hmac_secret`. The signed message is the timestamp, a dot, and the exact request body bytes:

```
signature = hex( HMAC-SHA256( hmac_secret, timestamp + "." + body ) )
```

Compute it over the raw bytes you received, before any JSON parsing or re-encoding.

The body is:

```json
{
  "schema": "sherlock.export.v1",
  "test": true,
  "records": [{ "id": "01JB...", "stream": "events", "at": "2026-11-01T12:00:00Z", "body": { "...": "the event or audit document" } }]
}
```

`test` is present (and `true`) only for the dashboard's Test button; `records` is then empty.

## Verifying

1. Reject the request if either header is missing.
2. Reject if `abs(now - timestamp)` is more than 5 minutes. This bounds replay of a captured request. Retries of a failed batch are re-signed with a fresh timestamp, so a short window does not break retries.
3. Recompute the HMAC and compare in constant time (never `==` on strings).
4. Deduplicate on `records[].id` (delivery is at-least-once). `X-Sherlock-Delivery` differs on each attempt, so it is not a dedup key. If you want replay protection stricter than the time window, remember delivery ids you have seen for that window.
5. Answer `2xx` once the batch is safely stored. Answer `5xx`, `429` or `408` for "try again" (Sherlock honours `Retry-After` up to 5 minutes). Any other `4xx`, including `401` and `403`, makes Sherlock discard the batch.

## Go

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func verify(secret []byte, r *http.Request, maxSkew time.Duration) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 16<<20))
	if err != nil {
		return nil, false
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Sherlock-Timestamp"), 10, 64)
	if err != nil {
		return nil, false
	}
	if d := time.Since(time.Unix(ts, 0)); d > maxSkew || d < -maxSkew {
		return nil, false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Sherlock-Signature"), "sha256="))
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return body, hmac.Equal(got, mac.Sum(nil))
}
```

## Python

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes, max_skew: int = 300) -> bool:
    ts = headers.get("X-Sherlock-Timestamp", "")
    sig = headers.get("X-Sherlock-Signature", "")
    if not ts.isdigit() or not sig.startswith("sha256="):
        return False
    if abs(time.time() - int(ts)) > max_skew:
        return False
    expected = hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig[len("sha256="):], expected)
```

## Rotating the secret

The secret needs at least 32 bytes (generate with `openssl rand -hex 32`). To rotate without losing data: make the receiver accept both the old and the new secret, change `hmac_secret` in the exporter (batches already spooled are signed at send time, so they use the new secret), then drop the old secret from the receiver once `sherlock_exporter_pending` is back to zero.
