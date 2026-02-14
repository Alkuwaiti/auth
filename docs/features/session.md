## Refresh Token Rotation

The `RefreshToken` operation issues a new access token and rotates the refresh token while enforcing strict session integrity and compromise detection.

This flow is designed to prevent replay attacks and detect token theft.

---

### Flow

1. **Feature Flag Validation**
   - The operation is blocked if refresh tokens are disabled.
   - Prevents partial or unsupported authentication flows.

2. **Session Lookup**
   - The session is retrieved using the provided refresh token.
   - If no session is found, a generic invalid credentials error is returned.
   - The system does not reveal whether the token exists.

3. **Session Integrity Checks**

   The following conditions immediately invalidate the request:

   - **Session already compromised**
   - **Session expired**
   - **Session revoked**

4. **Token Reuse Detection (Replay Protection)**

   If a revoked refresh token is reused:

   - The event is treated as a potential attack.
   - All sessions for the user are revoked and marked as compromised.
   - An audit log entry is created.
   - The request is rejected.

   This protects against stolen refresh token reuse.

5. **User Validation**
   - The associated user is retrieved.
   - Deleted accounts are rejected.
   - The client is not informed of account status.

6. **Refresh Token Rotation**
   - A new refresh token is generated.
   - The existing session is atomically rotated:
     - Old session is revoked (rotation reason recorded).
     - New refresh token replaces the old one.
     - Metadata (IP address, user agent) is recorded.

7. **Access Token Issuance**
   - A new access token is generated.
   - User roles and identity claims are embedded.

8. **Observability**
   - The entire operation is wrapped in a distributed trace span.
   - Security-relevant states are recorded.

---

### Security Guarantees

- Refresh tokens are single-use.
- Reuse of revoked tokens triggers full session compromise handling.
- Session expiration is enforced server-side.
- Deleted users cannot obtain new tokens.
- All token rotation events are auditable.
- Replay attacks are mitigated.

---

### Session Security Model

The refresh flow implements **rotation-based session security**:

- Every refresh invalidates the previous token.
- Reuse of an old token is treated as compromise.
- Compromise triggers global session revocation.
- Metadata (IP, user agent) is tracked for auditing and investigation.

This model aligns with modern secure authentication practices used in production SaaS systems.

---

### Design Notes

- Token rotation is performed at the persistence layer to ensure consistency.
- Generic error responses prevent token enumeration.
- Audit logging captures suspicious activity.
- Distributed tracing enables end-to-end visibility of session lifecycle events.

## Logout

The `Logout` operation revokes the user's active session associated with a given refresh token, ensuring the session cannot be reused and capturing the event for auditing.

---

### Flow

1. **Session Lookup**
   - The session corresponding to the provided refresh token is retrieved.
   - If no session exists (already logged out or invalid token), the operation is treated as successful to avoid leaking session state.

2. **Session Revocation**
   - The session is marked as revoked with the reason `Logout`.
   - Revocation prevents any further use of the refresh token or associated access tokens.

3. **Audit Logging**
   - An audit log entry is created capturing:
     - User ID
     - Action type (logout)
     - IP address
     - User agent
   - Failures in audit logging are logged but do not block logout completion.

4. **Observability**
   - The entire operation is wrapped in a distributed trace span.
   - Status and any operational issues are recorded for monitoring.

---

### Security Guarantees

- Logout revokes the refresh token and any associated session.
- Reusing a revoked or invalid refresh token is silently ignored to prevent session enumeration.
- Audit logs capture the logout event for traceability.

---

### Design Notes

- The logout process is idempotent: multiple calls with the same refresh token are safe.
- Session revocation ensures that access tokens cannot be refreshed after logout.
- Structured logging and distributed tracing provide operational visibility without leaking sensitive information.


