# Architecture

## Stack

| Concern | Choice |
|---|---|
| Language | Go |
| Transport | gRPC |
| Database | PostgreSQL |
| Observability | OpenTelemetry + Jaeger |
| Containerization | Docker |

### Language — Go

The service is written in Go. Its standard library and ecosystem are well-suited for building high-throughput network services, and the toolchain produces a single statically-linked binary that fits cleanly into a minimal Docker image.

### Transport — gRPC

All inter-service communication uses gRPC. Protobuf-defined contracts enforce a strict API schema, and HTTP/2 multiplexing keeps latency low under concurrent load.

### Database — PostgreSQL

PostgreSQL is the primary data store. The connection string follows the `postgres://` URI scheme and is passed in at runtime via environment variable.

### Observability — OpenTelemetry + Jaeger

Traces are instrumented with the OpenTelemetry Go SDK and exported to a Jaeger backend. This gives distributed trace visibility across service boundaries without coupling to a specific vendor.

### Containerization — Docker

The service ships as a Docker image built from a multi-stage Dockerfile. The final stage is a minimal image containing only the compiled binary.

---

## Database Diagram

![Database Diagram](../docs/db/authdb.erd.png)

## Overview

The schema is centered around the `users` table and branches out into authentication, authorization, session management, and auditing concerns. All tables use a UUID primary key (`id`) except for `user_roles` which uses a composite key of `user_id` + `role_id`, and `schema_migrations` which tracks migration state.

## Tables

### `users`

The core entity of the system. Stores credentials (`email`, `username`, `password_hash`), account state flags (`is_active`, `is_email_verified`, `mfa_enabled`), and soft-deletion fields (`deleted_at`, `deletion_reason`). Almost every other table has a foreign key pointing back to this one.

### `sessions`

Represents active user sessions. Each session holds a `refresh_token`, client metadata (`user_agent`, `ip_address`), and a full lifecycle of timestamps: `created_at`, `expires_at`, `revoked_at`, and `compromised_at`. The presence of `revocation_reason` and `compromised_at` suggests the service handles token compromise detection and explicit revocation as distinct events.

### `user_mfa_methods`

Stores the MFA methods enrolled by a user. The `type` column distinguishes between methods (e.g. TOTP, SMS), and `secret_ciphertext` holds the encrypted secret. The `confirmed_at` field indicates whether the method has been verified after enrollment, and `expires_at` supports time-limited methods.

### `mfa_challenges`

Tracks in-flight MFA verification attempts. Links to both `users` and a specific `mfa_method_id`, and records the `challenge_type`, `scope`, `attempts` count, and whether it has been `consumed_at`. The `expires_at` field enforces a time window for challenge completion.

### `mfa_backup_codes`

Holds hashed backup codes (`code_hash`) for account recovery when a primary MFA method is unavailable. Each code is tied to a user and tracks whether it has been `consumed_at`.

### `roles`

A simple lookup table defining the available roles in the system (`name`, `description`).

### `user_roles`

A join table that assigns roles to users. Records `assigned_at` to track when the assignment was made.

### `audit_logs`

An append-only log of security-relevant events. Each entry captures the `action` performed, `ip_address`, `user_agent`, the `actor_id` (who performed the action, which may differ from `user_id` in admin scenarios), and a `context` JSONB field for arbitrary structured metadata.

### `schema_migrations`

Managed by the migration tool (likely `golang-migrate`). Tracks the current schema `version` and a `dirty` flag that indicates whether the last migration run completed cleanly.

## Key Relationships

- `users` → `sessions` — one user, many sessions
- `users` → `user_mfa_methods` — one user, many enrolled MFA methods
- `users` → `mfa_backup_codes` — one user, many backup codes
- `users` → `mfa_challenges` — one user, many in-flight challenges; each challenge also references a specific `user_mfa_methods` record
- `users` → `user_roles` → `roles` — many-to-many role assignment through the `user_roles` join table
- `users` → `audit_logs` — one user, many audit events
---

## Package Versioning

The service proto is defined under `package auth.v1`, following the [Buf](https://buf.build/) and Google AIP convention of embedding the version directly in the package name.

```protobuf
package auth.v1;
```

This matters because the package name is what gets compiled into the generated Go code, the reflection registry, and any client stubs. Versioning it from the start means you can introduce a `auth.v2` alongside `auth.v1` in the future without breaking existing clients — both versions can be served from the same process simultaneously if needed.

The practical rules this unlocks:

- **Additive changes are safe within `v1`** — adding new RPC methods or new optional fields to a message is non-breaking. Existing clients ignore what they don't know about.
- **Breaking changes require a new version** — removing or renumbering fields, changing field types, or renaming RPCs should be done in `auth.v2`, not by mutating `auth.v1`.
- **`v1` implies stability** — once you ship `auth.v1` to consumers, treat it as a contract. A package named `auth.v1beta` or `auth.v1alpha` signals that breaking changes are still on the table.

## Unsafe Server

The generated `authv1.UnsafeAuthServiceServer` interface is embedded in your server struct instead of the safe `authv1.UnimplementedAuthServiceServer`.

```go
type Server struct {
    authv1.UnsafeAuthServiceServer
    // ...
}
```

The difference is intentional but worth understanding:

| | `UnimplementedAuthServiceServer` | `UnsafeAuthServiceServer` |
|---|---|---|
| Unimplemented methods | Return `codes.Unimplemented` at runtime | **Compile error** |
| Adding a new RPC to the proto | Silently passes at compile time | **Breaks the build** |
| Safety guarantee | You can forget to implement a method | You cannot ship unimplemented methods |

Using `UnsafeAuthServiceServer` is the stricter choice — if a new RPC is added to the `.proto` file and regenerated, the service **will not compile** until that method is implemented. This is generally the right default for an auth service where silently returning `Unimplemented` on a security-sensitive endpoint would be a worse outcome than a broken build.

The tradeoff is that it makes proto evolution slightly more friction-heavy: adding a new RPC to `auth.v1` immediately becomes a mandatory implementation task rather than something you can defer. For a small, focused service this is usually fine and preferable.


## CI

### Go CI (Active)

Runs on every push and pull request targeting `main`. The pipeline checks out the code, sets up Go, tidies dependencies, builds the binary, runs the integration test suite, and lints with `golangci-lint`.

```yaml
name: Go CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: 1.25
    - name: Install dependencies
      run: go mod tidy
    - name: Build
      run: go build -v ./...
    - name: Run tests
      run: go test -tags=integration ./...
    - name: Run golangci-lint
      uses: golangci/golangci-lint-action@v6
      with:
        args: --build-tags=integration
```

### Build & Push Image (Planned)

This workflow is defined but currently commented out. Once a container registry target is confirmed, it will build the Docker image, tag it with the commit SHA, and push it to the GitHub Container Registry (GHCR).

```yaml
# name: Build & Push Image
#
# on:
#   push:
#     branches: [main]
#
# permissions:
#   contents: read
#   packages: write
#
# jobs:
#   build-and-deploy:
#     runs-on: ubuntu-latest
#
#     steps:
#       - name: Checkout
#         uses: actions/checkout@v4
#
#       - name: Set up Go
#         uses: actions/setup-go@v5
#         with:
#           go-version: 1.25
#
#       - name: Run tests
#         run: go test -tags=integration ./...
#
#       - name: Log in to GHCR
#         run: echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
#
#       - name: Set image name
#         run: |
#           echo "IMAGE=ghcr.io/${GITHUB_REPOSITORY,,}/auth-service:${GITHUB_SHA}" >> $GITHUB_ENV
#
#       - name: Build & push image
#         run: |
#           docker build -t $IMAGE .
#           docker push $IMAGE
```

---

## Deployment

The service is designed to be deployed on Kubernetes using [Kustomize](https://kustomize.io/) for environment-specific configuration. Manifests and overlays will live under a `k8s/` directory in the repository. This work is deferred until a cluster is available.
