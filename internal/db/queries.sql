-- users

-- name: CreateUser :one
INSERT INTO users (id, username, email, password_hash , created_at, updated_at)
VALUES ($1, $2, $3, $4, NOW(), NOW())
RETURNING *;

-- name: UserExistsByEmail :one
SELECT EXISTS (
  SELECT 1 FROM users WHERE email = $1
);

-- name: UserExistsByUsername :one
SELECT EXISTS (
  SELECT 1 FROM users WHERE username = $1
);

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users
SET password_hash = $1
WHERE id = $2;


-- sessions

-- name: GetSessionByRefreshToken :one
SELECT * FROM sessions WHERE refresh_token = $1;

-- name: CreateSession :one
INSERT INTO sessions (user_id, refresh_token, user_agent, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: RevokeSession :exec
UPDATE sessions 
SET 
  revoked_at = NOW(),
  revocation_reason = $1
WHERE id = $2
AND revoked_at IS NULL;

-- name: RevokeAllUserSessions :exec
UPDATE sessions
SET 
  revoked_at = NOW(),
  revocation_reason = $1
WHERE user_id = $2
AND revoked_at IS NULL;

-- name: MarkSessionsCompromised :exec
UPDATE sessions
SET compromised_at = NOW()
WHERE user_id = $1
  AND compromised_at IS NULL;


-- audit

-- name: CreateAuditLog :one
INSERT INTO auth_audit_logs (user_id, action, ip_address, user_agent)
VALUES ($1, $2, $3, $4)
RETURNING *;


