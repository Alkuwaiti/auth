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

