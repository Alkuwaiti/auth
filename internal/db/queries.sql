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
INSERT INTO audit_logs (user_id, action, ip_address, user_agent, actor_id, context)
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
  user_id, type, secret_ciphertext, expires_at
)
VALUES ($1, $2, $3, now() + interval '10 minutes')
RETURNING *;

-- name: DeleteExpiredUnconfirmedMethods :exec
DELETE FROM user_mfa_methods
WHERE
  user_id = $1
  AND type = $2
  AND confirmed_at IS NULL
  AND expires_at < now();

-- name: GetMFAMethodsConfirmedByUser :many
SELECT id, user_id, type, confirmed_at, created_at
FROM user_mfa_methods
WHERE user_id = $1
  AND confirmed_at IS NOT NULL;

-- name: ConfirmUserMFAMethod :exec
UPDATE user_mfa_methods
SET
  confirmed_at = now(),
  expires_at = NULL
WHERE id = $1
  AND confirmed_at IS NULL;

-- name: CreateChallenge :one
INSERT INTO mfa_challenges (
  user_id, mfa_method_id, challenge_type, expires_at, scope
)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetChallengeByID :one
SELECT *
FROM mfa_challenges
WHERE id = $1;

-- name: ConsumeChallenge :exec
UPDATE mfa_challenges
SET consumed_at = now()
WHERE id = $1
  AND consumed_at IS NULL;

-- name: UserHasActiveMFAMethodByType :one
SELECT COUNT(*) > 0 AS exists
FROM user_mfa_methods
WHERE user_id = $1
  AND type = $2
  AND confirmed_at IS NOT NULL;

-- name: UserHasActiveMFAMethod :one
SELECT COUNT(*) > 0 AS exists
FROM user_mfa_methods
WHERE user_id = $1
  AND confirmed_at IS NOT NULL;

-- name: GetMFAMethodByID :one
SELECT * FROM user_mfa_methods
WHERE id = $1;

-- name: GetConfirmedMFAMethodByType :one
SELECT * FROM user_mfa_methods
WHERE user_id = $1 
  AND type = $2 
  AND confirmed_at IS NOT NULL;

-- name: IncrementChallengeAttempts :exec
UPDATE mfa_challenges
SET attempts = attempts + 1
WHERE id = $1;

-- name: LockActiveTOTPChallenge :one
SELECT
  c.id            AS challenge_id,
  c.user_id,
  c.attempts,
  m.id            AS method_id,
  m.secret_ciphertext
FROM mfa_challenges c
JOIN user_mfa_methods m
  ON m.id = c.mfa_method_id
 AND m.user_id = c.user_id
WHERE
  c.id = $1
  AND c.expires_at > NOW()
  AND c.consumed_at IS NULL
  AND m.type = 'totp'
  AND m.confirmed_at IS NOT NULL
FOR UPDATE;

-- name: InsertBackupCodes :exec
INSERT INTO mfa_backup_codes (user_id, code_hash)
SELECT $1, unnest($2::text[]);

-- name: DeleteBackupCodesForUser :exec
DELETE FROM mfa_backup_codes
WHERE user_id = $1;

-- name: GetUserBackupCodes :many
SELECT * FROM mfa_backup_codes
WHERE user_id = $1 AND consumed_at IS NULL;

-- name: ConsumeBackupCode :exec
UPDATE mfa_backup_codes
SET consumed_at = NOW()
WHERE id = $1
  AND consumed_at IS NULL;
