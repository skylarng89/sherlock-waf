# Running the control plane

`sherlock run` without `--config` starts the full node: the data plane (the WAF proxy) driven by a database, plus the API and dashboard over TLS. `sherlock run --config sherlock.yaml` still runs the data plane alone from a file (see the file-config quickstart).

## First start

A fresh node has **no users and no configuration**, and no default password. Either create the first administrator from the command line:

```sh
sherlock user create --admin ada          # prompts for a password (12+ characters)
sherlock run                              # API on https://127.0.0.1:9443
```

or start the server and use the dashboard's setup page: it asks for the one-time setup token, which the server wrote to `<data-dir>/setup-token` (mode 0600; the log names the file but never prints the token). The token works once and the page closes itself as soon as a user exists.

The server logs the SHA-256 of its public key (`tls_spki_sha256`) at start. The certificate is self-signed until you supply your own (`SHERLOCK_ADMIN_TLS_CERT` and `SHERLOCK_ADMIN_TLS_KEY`); pin the logged value when you script against it.

Sign in through the dashboard or API. Every account must enrol an authenticator app at first sign-in.

## Where state lives

| Setting | Default | Notes |
| --- | --- | --- |
| `--data-dir` | `$XDG_DATA_HOME/sherlock` | node key (`node.key`, mode 0600), TLS identity, SQLite database, event files |
| `--database-url` / `SHERLOCK_DATABASE_URL` | `<data-dir>/sherlock.db` | `postgres://…` or a SQLite path |
| `SHERLOCK_ADMIN_LISTEN` / `--listen` | `127.0.0.1:9443` | control plane address |
| `SHERLOCK_ADMIN_ALLOWED_CIDRS` | any | comma-separated CIDRs allowed to connect |
| `SHERLOCK_NODE_KEY_FILE` | `<data-dir>/node.key` | key that encrypts stored secrets; back it up with the database |

Until a configuration exists the node is alive (`/healthz`) but not ready (`/readyz` is 503) and proxies nothing. The first `PUT /api/v1/config` (or `sherlock config import`) needs no `If-Match`; later changes do.

## Command line

```sh
sherlock user create|reset-password|reset-mfa <username>
sherlock token create --user ada --name ci --scope write [--cidr 10.0.0.0/8] [--expires-in 720h]
sherlock config validate sherlock.yaml          # offline check, touches nothing
sherlock config export [-o sherlock.yaml]       # live configuration as YAML
sherlock config import sherlock.yaml            # fresh node only
sherlock config apply  sherlock.yaml            # replace; no-op when identical
sherlock hash-password                          # argon2id hash for a site password gate
sherlock audit verify                           # checks the audit hash chain
sherlock secrets rotate-key                     # re-encrypt secrets under a new node key
```

Passwords are read from a prompt, or from stdin with `--password-stdin`; never from a flag or the environment. `token create` prints the secret once on stdout.

`config import|apply` and `secrets rotate-key` change state that a running server holds in memory, so by default they refuse to run while a server is using the data directory. Against a running node, use its API instead:

```sh
sherlock config apply sherlock.yaml --server https://127.0.0.1:9443 --token "$SHERLOCK_TOKEN" --tls-pin <spki-sha256>
```

Rotating the node key needs the server stopped.

## Export and import

`config export` followed by `config import` on a fresh node reproduces the same configuration, and therefore the same compiled proxy configuration.
