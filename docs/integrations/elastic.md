# Elastic

Two supported routes: OTLP (preferred) straight to Elastic's managed OTLP endpoint or through an OpenTelemetry Collector, or the signed webhook through a small receiver of your own.

## Route 1: OTLP

### Prerequisites

- **Elastic Cloud:** the Managed OTLP endpoint (available on Elastic Cloud Serverless, and on Elastic Cloud Hosted from version 9.0 in supported regions; **verify against your deployment** that it is enabled). Copy the endpoint from the Cloud Console: your deployment → Manage → Application endpoints → Managed OTLP. Create an API key permitted to ingest.
- **Self-managed Elastic:** run an OpenTelemetry Collector (contrib or Elastic's distribution) with an OTLP receiver and the Elasticsearch exporter, and point Sherlock at the receiver (`http://collector:4318` or gRPC `collector:4317`).

Source: [Elastic Managed OTLP Endpoint GA on Elastic Cloud Hosted](https://www.elastic.co/observability-labs/blog/elastic-managed-otlp-endpoint-ga-elastic-cloud-hosted).

### Sherlock settings

Managed endpoint over OTLP/HTTP (Sherlock appends `/v1/logs` to the endpoint):

<!-- validate:otlp -->

```json
{
  "endpoint": "https://my-deployment.ingest.example.elastic.cloud",
  "protocol": "http",
  "headers": { "Authorization": "ApiKey BASE64_API_KEY" },
  "compression": "gzip"
}
```

Self-managed Collector on a private network, gRPC, TLS with a private CA:

<!-- validate:otlp -->

```json
{
  "endpoint": "collector.example.internal:4317",
  "protocol": "grpc",
  "tls": { "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n" },
  "resource_attributes": { "deployment.environment": "production" }
}
```

(A bare `host:port` with `grpc` means TLS; use `http://host:port` plus `"allow_http": true` for cleartext on a trusted network. gzip applies to HTTP only.)

Use stream `events`, or `both`; each OTLP log record's body is the full JSON document, with attributes `sherlock.event.id`, `sherlock.site_id`, `sherlock.action`, `client.address`, `http.request.method`, `url.path`, `http.response.status_code`, `sherlock.rule_ids` for events and `sherlock.audit.*` for audit records. Resource defaults: `service.name=sherlock-waf`, `service.version`, `host.name`.

Elastic routes OTLP logs it receives to a default data stream (`logs-generic.otel-default` per the Elastic announcement); to send Sherlock's logs to their own dataset, set the `data_stream.dataset` attribute as Elastic documents (**verify against your version** whether it must be a resource or log attribute; Sherlock lets you add resource attributes with `resource_attributes`).

### Verify

1. **Test** button in Sherlock: a log record "Sherlock exporter connectivity test" with `sherlock.stream=test` should appear in Discover / Logs.
2. Trigger a real event and search for `sherlock.event.id`.
3. `sherlock_exporter_sent_total` increases.

## Route 2: webhook

Elasticsearch ingest pipelines cannot verify an HMAC, so put a verifying receiver in front (a small service, or your API gateway) that follows [webhook-signature.md](webhook-signature.md) and then indexes `records[].body` with the Bulk API using `records[].id` as `_id`. That also gives you deduplication for free, because a repeated bulk index of the same `_id` overwrites rather than duplicates.

<!-- validate:webhook -->

```json
{
  "url": "https://ingest-proxy.example.internal/sherlock",
  "hmac_secret": "REPLACE_WITH_openssl_rand_-hex_32_OUTPUT_0123456789",
  "headers": { "X-Tenant": "soc" }
}
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Test says unauthorized (permanent) | API key format `ApiKey <base64>` in the `Authorization` header; key privileges |
| Test fails to connect | endpoint reachable from the Sherlock node; for gRPC the endpoint needs HTTP/2 end to end (some proxies strip it) |
| `rejected` drops increase | the receiver answers 4xx for a batch (schema, auth); look at the exporter's last error |
| Records arrive but fields are in `body` only | expected: the log body is the JSON document; add an ingest pipeline or Collector processor to parse it |
| Duplicates | at-least-once delivery; use `sherlock.event.id` as the document id |

## Security notes

The API key is a header value: Sherlock stores it encrypted and masks it. Create a key with ingest-only privileges and rotate it by editing the exporter (leave other fields as they are). Never use `allow_http` across an untrusted network.
