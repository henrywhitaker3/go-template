-- name: GetUserById :one
SELECT
    *
FROM
    users
WHERE
    id = $1
LIMIT
    1;

-- name: GetUserByEmail :one
SELECT
    *
FROM
    users
WHERE
    email = $1
LIMIT
    1;

-- name: CreateUser :one
INSERT INTO
    users(id, name, email, PASSWORD)
VALUES
    ($1, $2, $3, $4)
RETURNING
    *;

-- name: DeleteUser :exec
UPDATE
    users
SET
    deleted_at = EXTRACT(
        epoch
        FROM
            NOW()
    )
WHERE
    id = $1;

-- name: MakeAdmin :one
UPDATE
    users
SET
    admin = TRUE,
    updated_at = $2
WHERE
    id = $1
RETURNING
    *;

-- name: RemoveAdmin :one
UPDATE
    users
SET
    admin = false,
    updated_at = $2
WHERE
    id = $1
RETURNING
    *;

-- name: CreateRefreshToken :one
INSERT INTO
    refresh_tokens (id, user_id, hash, expires_at)
VALUES
    ($1, $2, $3, $4)
RETURNING
    *;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM
    refresh_tokens
WHERE
    expires_at < $1;

-- name: DeleteRefreshTokenByHash :exec
DELETE FROM
    refresh_tokens
WHERE
    hash = $1;

-- name: GetRefreshTokenByHash :exec
SELECT
    *
FROM
    refresh_tokens
WHERE
    hash = $1;
