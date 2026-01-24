-- users

-- name: CreateUser :one
INSERT INTO users (id, username, email, password_hash , created_at, updated_at)
VALUES ($1, $2, $3, $4, NOW(), NOW())
RETURNING *;

-- name: UserExists :one
SELECT EXISTS (
  SELECT 1 FROM users WHERE username = $1 OR email = $2
);


-- name: GetUserByEmail :one
SELECT
  u.*,
  ARRAY_AGG(r.name)::text[] AS roles
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.email = $1
GROUP BY u.id;

-- name: GetUserByID :one
SELECT
  u.*,
  ARRAY_AGG(r.name)::text[] AS roles
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.id = $1
GROUP BY u.id;

-- name: UpdatePassword :exec
UPDATE users
SET password_hash = $1
WHERE id = $2;

-- name: DeleteUser :execrows
UPDATE users
SET
  deleted_at = NOW(),
  deletion_reason = $1
WHERE id = $2
  AND deleted_at IS NULL;


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

-- name: CreateAuditLog :exec
INSERT INTO auth_audit_logs (user_id, action, ip_address, user_agent, actor_id, context)
VALUES ($1, $2, $3, $4, $5, $6);


-- authorization

-- name: GetRoleIDByName :one
SELECT id
FROM roles
WHERE name = $1;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id, assigned_at)
VALUES ($1, $2, NOW());

-- mfa

-- name: CreateUserMFAMethod :one
INSERT INTO user_mfa_methods (
  user_id, type, secret_ciphertext
)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetMFAMethodsConfirmedByUser :many
SELECT id, user_id, type, confirmed_at, created_at
FROM user_mfa_methods
WHERE user_id = $1
  AND confirmed_at IS NOT NULL;

-- name: ConfirmUserMFAMethod :exec
UPDATE user_mfa_methods
SET confirmed_at = now()
WHERE id = $1
  AND confirmed_at IS NULL;

-- name: CreateChallenge :one
INSERT INTO mfa_challenges (
  id, user_id, mfa_method_id, challenge_type, expires_at
)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveChallenge :one
SELECT id, user_id, mfa_method_id, expires_at, consumed_at
FROM mfa_challenges
WHERE id = $1
  AND consumed_at IS NULL
  AND expires_at > now();

-- name: ConsumeChallenge :exec
UPDATE mfa_challenges
SET consumed_at = now()
WHERE id = $1
  AND consumed_at IS NULL;

-- name: UserHasActiveMFAMethod :one
SELECT COUNT(*) > 0 AS exists
FROM user_mfa_methods
WHERE user_id = $1
  AND type = $2
  AND confirmed_at IS NOT NULL;

-- name: GetMFAMethodByID :one
SELECT * FROM user_mfa_methods
WHERE id = $1;

