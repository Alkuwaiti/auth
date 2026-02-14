# Auth Service

I came up with the idea of creating this Auth Service as a way to plug and play whenever I have an actual SaaS business. For it to be used as one service that'll produce Kafka events and orchestrate authentication across other future services. I was always ambitious with this project, and wanted to use all the available cutting edge tools (hopefully without getting cut). I'll briefly mention the tools used in this project. The only big IF case here is that I have a grpc server, which I need a grpc-gateway for. 

## Overview

The Auth Service is responsible for:

- User authentication
- Session management
- Multi-factor authentication (TOTP, backup codes)
- Step-up challenges
- Token issuance (access & refresh tokens)

It is designed to be used in a microservices architecture.

## Architecture

- Language: Go
- Transport: gRPC
- Database: PostgreSQL
- Observability: OpenTelemetry + Jaeger
- Containerization: Docker

## Features

- Password-based authentication
- TOTP-based MFA
- Backup codes
- Step-up authentication challenges
- Challenge attempt limiting
- Token rotation
- Distributed tracing

## Database Design

Core tables:

- users
- mfa_methods
- mfa_challenges
- sessions
- refresh_tokens

## First Time Setup

1. install dependencies

```bash
make tools
```
2. Start dependencies:

```bash
docker-compose up -d
```

3. Run migrations:

```bash
make run-migrations
```

4. shut down dependencies:

```bash
docker-compose down
```

## Run Locally

```bash
make run
```

## Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| DATABASE_URL | PostgreSQL connection string | Yes |
| JWT_SECRET | Signing key for tokens | Yes |
| TOTP_ISSUER | Issuer name for authenticator apps | Yes |

