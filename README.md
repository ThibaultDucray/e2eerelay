# Relay

Copyright (c) 2026 Thibault Ducray. Licensed under the MIT License — see [LICENSE](LICENSE).

A small end-to-end-encrypted (E2EE) message relay server. It stores and forwards
opaque ciphertext between registered devices; it never sees plaintext, and only
devices that pass the registration challenge (proving knowledge of a shared
master key, out of band) can register and exchange messages. See `doc/` for the
full protocol, client, and server specifications.

## Running locally

```
go run ./cmd/relay/
```

Or build first, then run:

```
go build -o relay ./cmd/relay/
./relay
```

The server requires a master key to be configured (see below) — it will refuse
to start without one.

Once started, hit `http://localhost:8080/relay/v3/health` to verify it's up.

## Configuration

All configuration is via environment variables.

### Required

| Variable | Description |
|---|---|
| `MASTER_KEY_B64URL` | Master key for the registration challenge, base64url-encoded (no padding), minimum 16 bytes (32 recommended). |
| `MASTER_KEY` | Alternative to `MASTER_KEY_B64URL`: the master key as raw text, minimum 16 bytes. |

Exactly one of these must be set. **Keep this key secret** — anyone who has it
can register a device against your relay. Generate one with, e.g.:

```
openssl rand -base64url 32
```

### Optional (defaults shown)

```
PORT=8080
DATABASE_URL=./data/relay.db     # SQLite by default; use postgres://... for production
DEFAULT_TTL_SEC=1296000          # 15 days
MAX_TTL_SEC=2592000              # 30 days
MAX_WAIT_MS=30000                # 30s long-poll cap
CLEANUP_INTERVAL_SEC=600         # 10 min cleanup job
TOKEN_TTL_SEC=31536000           # 1 year
TOKEN_IDLE_DAYS=182              # 6 months
```

Example with a custom port and SQLite path:

```
PORT=9090 DATABASE_URL=myrelay.db go run ./cmd/relay/
```

Example with PostgreSQL:

```
DATABASE_URL=postgres://user:pass@host/dbname go run ./cmd/relay/
```

The server logs structured JSON to stdout.

## Documentation

See `doc/`:
- `E2EE-Relay-API-Spec-v3.md` — HTTP API specification
- `E2EE-Relay-Client-Spec-v3.md` — client integration guidance
- `E2EE-Relay-Server-Spec-Go-v3.md` — server implementation notes

## License

MIT — see [LICENSE](LICENSE).
