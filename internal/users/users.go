package users

import (
	"context"
	"database/sql"
	"time"

	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/go-template/internal/crypto"
	"github.com/henrywhitaker3/go-template/internal/uuid"
)

type User struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func mapUser(u *queries.User) *User {
	return &User{
		ID:        uuid.UUID(u.ID),
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: time.Unix(u.CreatedAt, 0),
		UpdatedAt: time.Unix(u.UpdatedAt, 0),
	}
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
	return mapUser(user), nil
}

func (u *Users) GetByEmail(ctx context.Context, email string) (*User, error) {
	user, err := u.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return mapUser(user), err
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
	return mapUser(user), nil
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
	return mapUser(user), nil
}