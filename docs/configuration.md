# Configuration

The service is configured via environment variables or a config file. All fields are listed below.

> **Never commit real secrets to version control.** The values shown here are examples only. In production, inject secrets via environment variables, a secrets manager, or a tool like [Vault](https://www.vaultproject.io/).

## Reference

| Field | Type | Example | Description |
|---|---|---|---|
| `app_name` | string | `MyApp` | Name of the service, used in logs and trace metadata. |
| `log_level` | string | `debug` | Log verbosity. Accepted values: `debug`, `info`, `warn`, `error`. Use `info` or above in production. |
| `database_url` | string | `postgres://user:pass@localhost:5432/authdb?sslmode=disable` | PostgreSQL connection string. See [Database](#database) below. |
| `jwt_key` | secret | — | Signing key for JWT access tokens. Should be a long, random string. |
| `aes_key` | secret | — | AES encryption key used for encrypting sensitive fields (e.g. MFA secrets). Must be a 64-character hex string (32 bytes). |
| `refresh_enabled` | bool | `true` | Whether refresh token issuance is enabled. Set to `false` to issue short-lived access tokens only. |
| `max_challenge_attempts` | int | `5` | Maximum number of failed attempts allowed for an MFA challenge before it is invalidated. |
| `otlp_endpoint` | string | `localhost:4317` | OTLP gRPC endpoint for OpenTelemetry trace export. |
| `tracing_collector` | string | `some collector` | Human-readable name or address of the tracing collector, used in trace metadata. |

## Database

The `database_url` follows the standard PostgreSQL URI format:

```
postgres://<user>:<password>@<host>:<port>/<dbname>?<options>
```

The `sslmode=disable` option is acceptable for local development but should be set to `require` or `verify-full` in any environment that is not localhost.

## Secrets

Two fields require cryptographically strong values and must be treated as secrets:

**`aes_key`** must be exactly 64 hex characters (32 bytes). You can generate one with:
```bash
openssl rand -hex 32
```

**`jwt_key`** should be a long random string. You can generate one with:
```bash
openssl rand -base64 48
```

Both keys should be rotated according to your security policy. Rotating the `aes_key` requires a migration strategy for existing encrypted values in the database.

## Log Level

Set `log_level` to `debug` during development to get detailed output. In production, `info` is the recommended baseline — it surfaces meaningful events without the noise of debug traces.

## Tracing

The service exports traces via OTLP to the endpoint defined in `otlp_endpoint`. For local development this points to a Jaeger instance running on `localhost:4317`. In a deployed environment this should point to your collector sidecar or service.

