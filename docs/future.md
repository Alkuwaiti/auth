## Future Improvements

This project is intentionally built to evolve. Below are the next areas of focus, ranging from security enhancements to infrastructure maturity.

---

### Authentication & Security Enhancements

#### Trusted Devices
Allow users to mark devices as trusted after successful MFA verification.  
This would reduce friction for frequent logins while maintaining security through device fingerprinting and expiration policies.

#### WebAuthn Support
Introduce WebAuthn for phishing-resistant, passwordless authentication using hardware-backed credentials (e.g., security keys or platform authenticators).  
This would significantly strengthen the authentication model.

#### Email Verification
Add email verification flows during user registration to ensure account authenticity and improve trust boundaries.

#### Password Reset
Implement secure, token-based password reset functionality with proper expiration, replay protection, and audit logging.

#### Remember-Me Logic
Support long-lived sessions with carefully scoped refresh tokens and revocation strategies.

---

### MFA & Device Management

#### gRPC Endpoint for Step-up MFA
Expose a dedicated gRPC endpoint for step-up authentication challenges to better support sensitive operations across services.

#### Device Management UI
Allow users to view and manage:
- Active sessions
- Registered MFA methods
- Trusted devices  
This would improve transparency and user control.

---

### Resilience & Performance

#### Rate Limiting at API Gateway
Introduce rate limiting at the gateway level to mitigate brute-force attacks and abusive patterns before they hit the service core.

#### Redis-Backed Challenge Cache
Move short-lived challenges (e.g., MFA or step-up flows) to Redis for:
- Faster reads/writes
- Reduced database load
- Better horizontal scalability

---

### Event-Driven Architecture

#### Emit Auth Events
Publish authentication-related events (login, logout, MFA verified, password changed, etc.) to Kafka.  
This enables downstream services to react asynchronously and supports audit pipelines, notifications, and analytics.

---

### Infrastructure & Deployment

#### Kubernetes Deployment (Kustomize)
Deploy the service to Kubernetes using Kustomize for environment-specific overlays (dev, staging, prod).  
This will solidify the operational model once a cluster environment is available.

---

The overall direction is clear:  
Continue strengthening security guarantees, improve system resilience, and evolve the service into a production-grade authentication backbone for future SaaS systems.

