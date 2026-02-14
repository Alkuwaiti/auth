# Auth Service

I built this Auth Service with the intention of learning authentication and authorization properly — by actually building something in that domain.

That’s a big shift from how I used to approach topics like this. I would usually read articles, watch videos, and consume content from other creators, but I wouldn’t sit down and build the thing myself. This time, I decided to do exactly that and see where it would take me.

It turned out better than I expected — and the journey is far from over.

The idea evolved into creating a plug-and-play authentication core that I can drop into any future SaaS product I build — a dedicated service responsible for identity, security, and trust. Instead of baking auth logic into every application, this service stands on its own: orchestrating authentication flows, emitting Kafka events (soon), and integrating cleanly with other services in a distributed system (also soon).

From the start, I approached this project with ambition. I wanted it to feel production-ready — not just a fun little thing (although it continues to be so). That meant embracing strong engineering practices: gRPC for service-to-service communication (shoutout 🌧️), structured observability, containerization, CI pipelines, and clean architectural boundaries in code. The goal was to explore cutting-edge tools — ideally without getting cut in the process.

I plan to keep building on this, adding features gradually while continuously hardening the architectural integrity of the system. Right now, the feature set may look small for two months of work, but that’s intentional. A lot of effort went into handling edge cases properly and making sure the foundation is solid before expanding further.

The only major architectural “if” at the moment is transport exposure. Since the service runs as a gRPC server, it will require a gRPC-Gateway layer to expose HTTP/JSON endpoints when integrating with web clients or external systems. That piece is intentionally left as a future addition once the surrounding ecosystem solidifies. A good contender would be [ grpc-gateway ](https://github.com/grpc-ecosystem/grpc-gateway(https://github.com/grpc-ecosystem/grpc-gateway)) to save me from building that layer from scratch.

## Table of Contents
- [Setup](docs/setup.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Future Improvements](docs/future.md)
- [Features](docs/features/overview.md)
  - [Registration](docs/features/registration.md)
  - [sessions](docs/features/session.md)
  - [MFA](docs/features/mfa.md)

