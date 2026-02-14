# Auth Service

I came up with the idea of creating this Auth Service as a way to plug and play whenever I have an actual SaaS business. For it to be used as one service that'll produce Kafka events and orchestrate authentication across other future services. I was always ambitious with this project, and wanted to use all the available cutting edge tools (hopefully without getting cut). I'll briefly mention the tools used in this project. The only big IF case here is that I have a grpc server, which I need a grpc-gateway for. 

# Auth Service Documentation

## Table of Contents
- [Overview](docs/overview.md)
- [Setup](docs/setup.md)
- [Features](docs/features/overview.md)
  - [Registration](docs/features/registration.md)
  - [sessions](docs/features/session.md)
  - [MFA](docs/features/mfa.md)

## Architecture

- Language: Go
- Transport: gRPC
- Database: PostgreSQL
- Observability: OpenTelemetry + Jaeger
- Containerization: Docker

## Database Design

![Database Diagram](./docs/db/authdb.erd.png)


## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| DATABASE_URL | PostgreSQL connection string | Yes |
| JWT_SECRET | Signing key for tokens | Yes |
| TOTP_ISSUER | Issuer name for authenticator apps | Yes |

## Future Improvements

- Trusted devices
- WebAuthn support
- Rate limiting at API gateway
- Redis-backed challenge cache
- Email verification
- Password reset
- Device management UI
- Remember-me logic
- Emit auth events
- gRPC Endpoint for Step-up MFA
- K8s Kustomize

## Infrastructure

- gRPC
- golang
- github workflows
- docker-compose

## Feature Walkthrough

Auth service is versioned via protobuff. currently it is v1.
Client cmd for grpc testing

