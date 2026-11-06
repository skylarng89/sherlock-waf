# TLS and certificates

Each site chooses how it gets its certificate with `tls.mode`. Sherlock terminates TLS for every site that is not `none`, so the certificate it serves is the one your visitors see. This page covers the three modes, automatic certificates, uploading your own, renewal and expiry, and what to check when a certificate does not appear.

## Modes

| `tls.mode` | What it does |
| --- | --- |
| `acme` (default) | Sherlock obtains and renews a certificate for every host of the site from an ACME certificate authority (Let's Encrypt unless you set another). |
| `file` | Sherlock serves a certificate you supply: either an uploaded one (`cert_id`) or a pair of files on the node (`cert_file` and `key_file`). |
| `none` | The site is plain HTTP only. No certificate, no HTTP-to-HTTPS redirect and no HSTS header. Use it while testing behind another TLS terminator, not for production traffic. |

`cert_id`, `cert_file` and `key_file` are only valid with `mode: file`, and `cert_id` cannot be combined with the file pair. A configuration that breaks these rules is refused when you save it, with the field named.

For every site that is not `none`, requests on the HTTP port are answered with a `308` redirect to HTTPS. Requests for a host Sherlock does not know are answered with `421 Misdirected Request` on both ports. The listeners default to ports 80 and 443; change them with `sherlock run --http-port` and `--https-port`.

```yaml
global:
  acme: { email: security@example.com }      # optional; the CA contacts this address about your certificates
sites:
  - id: shop
    hosts: [shop.example.com, www.shop.example.com]
    tls: { mode: acme, min_version: "1.2", hsts: { enabled: true, max_age: 31536000, include_subdomains: false } }
    upstreams: { targets: ["10.0.0.5:8080"] }
```

## Automatic certificates (ACME)

With `mode: acme` the first HTTPS request for a host triggers issuance, and Sherlock renews the certificate before it expires without any action from you. Two global settings exist, both optional:

| Key | Meaning |
| --- | --- |
| `global.acme.email` | Contact address for the certificate authority. Must contain `@`. |
| `global.acme.ca` | ACME directory URL of another authority. Must be an `https` URL. Unset means Let's Encrypt. |

Sherlock has no setting for the ACME challenge type. Challenges are handled by the embedded Caddy with its defaults, which can use HTTP-01 on port 80 or TLS-ALPN-01 on port 443. What that means for you:

- Every host must resolve in public DNS to this node.
- Ports 80 and 443 must be reachable from the internet. A firewall that closes either can stop issuance.
- Host names that are not publicly resolvable cannot get a certificate this way. Use `mode: file` for internal names.

Certificates the authority issued are stored under the data directory (`<data-dir>/certificates/`). `sherlock backup` includes the ACME certificates and account state, so a restored node does not have to ask the authority again; uploaded certificates are in the database and travel with it ([backup and restore](backup-restore.md)).

## Using your own certificate

1. In the dashboard open **Certificates** and use **Upload a certificate**, or send `POST /certificates` with `name`, `certificate_pem` (the chain, server certificate first) and `private_key_pem`.
2. Set the site to `tls: { mode: file, cert_id: <id> }`. The id is shown in the table and returned by the upload.

Sherlock checks the upload before storing it and refuses it with a message when:

- the first certificate is a CA rather than the server certificate;
- the certificate has expired or is not valid yet;
- it has no DNS names (subject alternative names);
- the private key is passphrase protected, does not match the certificate, or is weak (RSA below the minimum size, or an unsupported elliptic curve);
- the chain has too many certificates or the text contains anything other than PEM certificates.

The key is stored sealed with the node key and is never shown again, and the key is not part of `GET /certificates`. To replace an expiring certificate, upload the new one, switch the site to the new id, then delete the old one. Deleting a certificate that a site still uses is refused (`409`).

A wildcard certificate (`*.example.com`) covers the hosts one label below it. If a site host is not listed on the certificate, the Certificates page shows that host as failed with "The uploaded certificate does not list this host."

For a pair of files on the node (`cert_file` and `key_file`, PEM), Sherlock reads them when it loads the configuration. After you replace both files, restart the service so it loads the renewed certificate.

## Renewal and expiry

- **Dashboard.** The Certificates page lists uploaded certificates with their expiry and flags a certificate that expires within 30 days or has already expired. Its **Automatic certificate status** table shows one row per host:

  | State | Meaning |
  | --- | --- |
  | `pending` | No certificate yet. Check DNS and ports 80 and 443. |
  | `issued` | A valid certificate is installed. Automatic ones renew on their own. |
  | `failed` | An uploaded certificate no longer exists or does not list the host. |
  | `not_applicable` | The host does not use a certificate (`mode: none`, or a file pair on disk). |

  The same data is available from `GET /certificates/acme-status`.
- **Metric.** `sherlock_cert_expiry_seconds{site,host}` is the number of seconds until the certificate serving the host expires, refreshed every 60 seconds; it goes negative once expired. A host has no series until its certificate exists, and wildcard ACME hosts have none. See [deployment](../operations/deployment.md).
- **Alert.** Create an alert rule of kind **Certificate expiring** with a number of days ([exporters and alerts](exporters-and-alerts.md)). It notifies your channels when a certificate expires in fewer days than that. Fourteen days leaves time to fix a failing renewal.

## Protocol version and HSTS

| Key | Default | Notes |
| --- | --- | --- |
| `tls.min_version` | `1.2` | `1.2` or `1.3`. Clients older than the minimum fail the handshake. |
| `tls.hsts.enabled` | `true` | Adds `Strict-Transport-Security` to responses. Never added for `mode: none`. |
| `tls.hsts.max_age` | `31536000` (one year) | Seconds. Must not be negative. |
| `tls.hsts.include_subdomains` | `false` | Adds `includeSubDomains`. Turn it on only when every subdomain serves HTTPS. |

HSTS tells browsers to refuse plain HTTP for the whole `max_age`. Test with a short `max_age` before leaving the default.

## Client certificates (mTLS) for APIs

To require client certificates on some paths, upload the CA certificates as a CA bundle and reference it from the site's API policy. The site then asks every client for a certificate, verifies the ones that are offered against the bundle, and refuses the paths you list without one. See [API protection](api-protection.md#mutual-tls). `POST /ca-bundles` takes certificates only, never private keys, and deleting a bundle that a policy uses is refused.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Certificate stays `pending` | The host must resolve to this node and ports 80 and 443 must be reachable from the internet. Look at the node log for the authority's error. Certificate authorities limit repeated failed attempts, so fix the cause before retrying many times. |
| Browser shows the wrong certificate or a name mismatch | The request's host is not in the site's `hosts`, or the uploaded certificate does not list it. |
| `421 Misdirected Request` | No site lists that host. Add it to `hosts`. |
| Upload refused | Read the message: it names the problem (expired, key mismatch, encrypted key, no DNS names). Decrypt the key first with `openssl pkey -in key.pem -out plain.pem`. |
| Saving the site is refused | `cert_id` with `mode: acme`, both `cert_id` and a file pair, or a missing key file. The error names the field. |
| Old clients cannot connect | `tls.min_version: "1.3"` excludes TLS 1.2 clients. |
