## Complete Login MFA

The `CompleteLoginMFA` operation finalizes a login attempt that requires multi-factor authentication (MFA). It verifies the provided MFA code and issues tokens if successful.

---

### Flow

1. **Challenge Verification**
   - The MFA challenge associated with the login attempt is verified and consumed.
   - Ensures that challenges are single-use and enforces attempt limiting.
   - Invalid or expired codes result in an error, preventing token issuance.

2. **User Retrieval**
   - The user associated with the challenge is fetched from the database.
   - Missing or deleted users trigger a generic invalid credentials error to prevent account enumeration.

3. **Token Issuance**
   - Upon successful MFA verification, access and refresh tokens are generated.
   - Audit logging records the MFA login event for traceability.

4. **Observability**
   - The operation is part of a distributed trace.
   - Key events and failures are recorded for monitoring and debugging.

---

### Security Guarantees

- MFA challenges are single-use and tied to a specific login attempt.
- Invalid codes do not reveal whether the user exists.
- Tokens are only issued after successful MFA verification.
- Audit logs capture the MFA login event for accountability.

---

### Design Notes

- The service decouples MFA verification from password validation to support step-up authentication.
- Finalizing login through a dedicated method ensures consistent token issuance and audit logging.
- Distributed tracing provides full visibility into MFA login attempts and failures.




## Enroll MFA Method

The `EnrollMFAMethod` operation allows a user to enroll a new multi-factor authentication (MFA) method, such as TOTP, while enforcing uniqueness, expiration cleanup, and secure secret handling.

---

### Flow

1. **User Context Retrieval**
   - The user ID and email are extracted from the request context.
   - Requests without valid user context are rejected.

2. **Method Type Validation**
   - The requested MFA method type is validated.
   - Invalid types result in a `ValidationError`.

3. **Check Existing Enrollment**
   - The service checks whether the user already has an active method of the same type.
   - Duplicate enrollment is rejected with a `BadRequestError`.

4. **Cleanup Expired/Unconfirmed Methods**
   - Any expired or unconfirmed MFA methods of the same type are deleted to avoid conflicts.

5. **TOTP Key Generation**
   - A new TOTP key is generated for the user using their email as the identifier.
   - The provisioning URI is derived for setup in an authenticator app.

6. **Secret Encryption**
   - The TOTP secret is encrypted before being persisted.
   - Plaintext secrets are never stored.

7. **Persistence**
   - The new MFA method is created in the database with the encrypted secret and metadata.

8. **Response**
   - Returns the newly created MFA method and a setup URI for the user to configure their authenticator.

9. **Observability**
   - The operation is wrapped in a distributed trace span.
   - Key events and errors are recorded for monitoring.

---

### Security Guarantees

- MFA secrets are encrypted at rest.
- Duplicate MFA enrollment is prevented.
- Expired/unconfirmed methods are cleaned up to prevent orphaned secrets.
- Sensitive information (like raw secrets) is never exposed in logs or responses.
- Traceability is provided for enrollment events.

---

### Design Notes

- The setup URI can be used to display a QR code for authenticator apps.
- Cleanup of expired/unconfirmed methods ensures that only valid MFA secrets exist for each user.
- Distributed tracing allows observability of enrollment and error paths.
- Structured logging captures operational and security-relevant events without leaking secrets.

## Confirm MFA Method

The `ConfirmMFAMethod` operation finalizes a user's MFA enrollment, verifying the provided TOTP code, marking the method as confirmed, and generating backup codes for recovery.

---

### Flow

1. **Method Retrieval**
   - The MFA method is retrieved from the database using its ID.
   - If the method does not exist, an error is returned.

2. **Enrollment Validation**
   - Checks that the method has not expired.
   - Prevents confirmation of already confirmed methods.

3. **Transactional Confirmation**
   - A database transaction is started to ensure atomicity.
   - The transaction ensures:
     - The method is confirmed.
     - Any previous backup codes are deleted.
     - New backup codes are generated and stored securely.
   - If any step fails, the transaction is rolled back.

4. **TOTP Verification**
   - The provided code is verified against the encrypted TOTP secret.
   - Invalid codes result in an `InvalidMFACodeError`.

5. **Backup Code Generation**
   - A fixed number of single-use backup codes are generated (e.g., 10).
   - Backup codes are hashed before storage; plaintext codes are only returned to the client once.

6. **Audit Logging**
   - An audit log is created capturing:
     - User ID
     - Action type (`ConfirmMFAMethod`)
     - Method type and ID
     - IP address and user agent
   - Ensures traceability of MFA confirmations.

7. **Observability**
   - The operation is wrapped in a distributed trace span.
   - Errors and key events are recorded for monitoring and debugging.

---

### Security Guarantees

- MFA methods cannot be confirmed after expiration.
- Methods cannot be confirmed more than once.
- Backup codes are generated securely and stored hashed.
- Transactional confirmation ensures atomicity: partial confirmation cannot occur.
- Audit logs provide accountability for MFA enrollment.

---

### Design Notes

- Transactional design prevents orphaned backup codes or inconsistent confirmation states.
- Backup codes provide a secure fallback for users who lose access to their authenticator.
- Distributed tracing allows monitoring of the confirmation process and early detection of errors.
- Structured logging ensures operational visibility without exposing sensitive secrets.

## Create Step-Up Challenge

The `CreateStepUpChallenge` operation generates a temporary MFA challenge for sensitive actions or step-up authentication flows, requiring users to re-verify their identity before proceeding.

---

### Flow

1. **User Context Retrieval**
   - The user ID is extracted from the request context.
   - Requests without a valid user context are rejected.

2. **Confirmed MFA Method Lookup**
   - The service fetches a confirmed MFA method of the specified type for the user.
   - If no confirmed method exists, an error is returned.

3. **Challenge Creation**
   - A new step-up MFA challenge is created in the database with:
     - User ID
     - MFA method ID
     - Scope of the challenge (e.g., `Login` or other sensitive operations)
     - Challenge type set to `StepUp`
   - Challenges are designed to be single-use and time-limited.

4. **Observability**
   - The operation is wrapped in a distributed trace span.
   - User ID and challenge creation status are recorded for monitoring and debugging.

5. **Response**
   - Returns the challenge ID, MFA method type, and expiration timestamp.
   - The client can use this ID to prompt the user for verification.

---

### Security Guarantees

- Challenges are bound to a specific user and MFA method.
- Single-use and time-limited to prevent replay attacks.
- Only confirmed MFA methods can be used for step-up challenges.
- Distributed tracing ensures visibility of challenge creation events.

---

### Design Notes

- Step-up challenges decouple sensitive operations from standard login flows.
- The challenge ID can be used in subsequent verification endpoints to enforce multi-factor authentication.
- This design allows fine-grained control over sensitive actions without requiring a full re-login.
- Structured logging and tracing provide operational insight without exposing sensitive data.

## Verify Step-Up Challenge

The `VerifyStepUpChallenge` operation validates a step-up authentication challenge, allowing users to authorize sensitive actions. It relies on the `VerifyAndConsumeChallenge` helper to securely handle MFA verification.

---

### Flow

1. **User Context Retrieval**
   - The user ID and email are extracted from the request context.
   - Requests without a valid user context are rejected.

2. **Challenge Lookup**
   - The step-up challenge is fetched from the database using the challenge ID.
   - Checks ensure the challenge belongs to the requesting user.

3. **Challenge Validity Checks**
   - Verifies the challenge is not expired.
   - Ensures the challenge has not already been consumed.
   - Unauthorized or invalid attempts trigger `ForbiddenError` or `BadRequestError`.

4. **MFA Verification (`VerifyAndConsumeChallenge`)**
   - The challenge is locked in a database transaction to prevent race conditions.
   - TOTP codes are verified against the stored secret.
   - Backup codes are checked as an alternate method of verification.
   - Invalid attempts increment the challenge attempt counter.
   - Single-use challenges are marked as consumed after successful verification.
   - Audit logs are created to record the consumption event.

5. **Step-Up Token Generation**
   - A short-lived step-up token is issued for the user.
   - The token is scoped to the sensitive operation for which the step-up challenge was created.

6. **Observability**
   - Distributed tracing spans record the operation for monitoring.
   - Key events and errors are logged in structured format for debugging and auditing.

7. **Response**
   - Returns a step-up token and its expiration time for use in sensitive operations.

---

### Security Guarantees

- Challenges are single-use and bound to a specific user and action.
- Expired or consumed challenges cannot be reused.
- Both TOTP and backup codes are supported for secure recovery.
- Challenge attempt limits prevent brute-force attacks.
- Transactions ensure atomicity: a challenge is only consumed if verification succeeds.
- Audit logs capture all consumption events without exposing sensitive data.

---

### Design Notes

- `VerifyAndConsumeChallenge` decouples the low-level MFA verification from the higher-level step-up flow.
- The design supports both TOTP and backup codes while enforcing a maximum number of attempts.
- Structured logging and distributed tracing provide operational visibility without leaking secrets.
- Step-up tokens are scoped to the action, preventing misuse outside their intended context.

