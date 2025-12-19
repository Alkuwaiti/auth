-- users
-- name: GetUserByID :one
SELECT * FROM users 
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1;

-- name: CreateUser :one
INSERT INTO users (username, email, password_hash , created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
RETURNING *;
