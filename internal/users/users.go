package users

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/go-template/internal/crypto"
	"github.com/henrywhitaker3/go-template/internal/uuid"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Admin     bool      `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func MapUser(u *queries.User) *User {
	return &User{
		ID:        uuid.UUID(u.ID),
		Email:     u.Email,
		Name:      u.Name,
		Admin:     u.Admin,
		CreatedAt: time.Unix(u.CreatedAt, 0),
		UpdatedAt: time.Unix(u.UpdatedAt, 0),
	}
}

func MapUsers(users []*queries.User) []*User {
	out := []*User{}
	for _, u := range users {
		out = append(out, MapUser(u))
	}
	return out
}

type Users struct {
	q *queries.Queries
}

func New(q *queries.Queries) *Users {
	return &Users{
		q: q,
	}
}

func (u *Users) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := u.q.GetUserById(ctx, id.UUID())
	if err != nil {
		return nil, err
	}
	return MapUser(user), nil
}

func (u *Users) GetByEmail(ctx context.Context, email string) (*User, error) {
	user, err := u.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return MapUser(user), err
}

type CreateParams struct {
	Name     string
	Email    string
	Password string
}

func (u *Users) CreateUser(ctx context.Context, params CreateParams) (*User, error) {
	id, err := uuid.Ordered()
	if err != nil {
		return nil, err
	}

	hash, err := crypto.HashPassword(params.Password)
	if err != nil {
		return nil, err
	}

	user, err := u.q.CreateUser(ctx, queries.CreateUserParams{
		ID:       id.UUID(),
		Name:     params.Name,
		Email:    params.Email,
		Password: hash,
	})
	if err != nil {
		return nil, err
	}
	return MapUser(user), nil
}

func (u *Users) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return u.q.DeleteUser(ctx, id.UUID())
}

func (u *Users) Login(ctx context.Context, email, password string) (*User, error) {
	user, err := u.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user.DeletedAt.Valid {
		return nil, sql.ErrNoRows
	}
	if err := crypto.VerifyPassword(password, user.Password); err != nil {
		return nil, err
	}
	return MapUser(user), nil
}

func (u *Users) CreateRefreshToken(
	ctx context.Context,
	user uuid.UUID,
	validity time.Duration,
) (string, error) {
	id, err := uuid.Ordered()
	if err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}

	token := make([]byte, 64)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	tokenS := hex.EncodeToString(token)

	_, err = u.q.CreateRefreshToken(ctx, queries.CreateRefreshTokenParams{
		ID:        id.UUID(),
		UserID:    user.UUID(),
		Hash:      crypto.Sum(tokenS),
		ExpiresAt: time.Now().Add(validity).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return tokenS, nil
}

func (u *Users) GetUserByRefreshToken(ctx context.Context, token string) (*User, error) {
	user, err := u.q.GetUserByRefreshToken(ctx, queries.GetUserByRefreshTokenParams{
		Hash:      crypto.Sum(token),
		ExpiresAt: time.Now().Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("get user by refresh token: %w", err)
	}
	return MapUser(user), nil
}

func (u *Users) DeleteRefreshToken(ctx context.Context, token string) error {
	if err := u.q.DeleteRefreshTokenByHash(ctx, crypto.Sum(token)); err != nil {
		return fmt.Errorf("delete refresh token by hash: %w", err)
	}
	return nil
}

func (u *Users) RotateRefreshToken(ctx context.Context, hash string) (string, error) {
	token := make([]byte, 64)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate new token: %w", err)
	}
	tokenS := hex.EncodeToString(token)

	if err := u.q.RotateRefreshToken(ctx, queries.RotateRefreshTokenParams{
		Newhash:     crypto.Sum(tokenS),
		Currenthash: crypto.Sum(hash),
	}); err != nil {
		return "", fmt.Errorf("update token hash: %w", err)
	}
	return tokenS, nil
}

func (u *Users) MakeAdmin(ctx context.Context, user *User) error {
	ud, err := u.q.MakeAdmin(ctx, queries.MakeAdminParams{
		ID:        user.ID.UUID(),
		UpdatedAt: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	*user = *MapUser(ud)
	return nil
}

func (u *Users) RemoveAdmin(ctx context.Context, user *User) error {
	ud, err := u.q.RemoveAdmin(ctx, queries.RemoveAdminParams{
		ID:        user.ID.UUID(),
		UpdatedAt: time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	*user = *MapUser(ud)
	return nil
}
