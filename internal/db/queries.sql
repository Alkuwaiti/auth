-- users

-- name: RegisterUser :one
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


-- sessions

-- name: GetSessionByRefreshToken :one
SELECT * FROM sessions WHERE refresh_token = $1;

-- name: CreateSession :exec
INSERT INTO sessions (user_id, refresh_token, user_agent, ip_address, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: RevokeSession :exec
UPDATE sessions 
SET revoked_at = NOW() 
WHERE id = $1
AND revoked_at IS NULL;

