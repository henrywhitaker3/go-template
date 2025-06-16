package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/henrywhitaker3/go-template/internal/users"
)

var (
	ErrInvalidated = errors.New("jwt has been invalidated")
)

func GenerateSecret(size int) (string, error) {
	secret := make([]byte, size/8)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}
	encoded := base64.RawStdEncoding.EncodeToString(secret)
	return fmt.Sprintf("base64:%s\n", encoded), nil
}

type Jwt struct {
	secret string
}

func New(secret string) *Jwt {
	return &Jwt{
		secret: secret,
	}
}

type userClaims struct {
	User *users.User
	jwt.StandardClaims
}

func (j *Jwt) NewForUser(user *users.User, expires time.Duration) (string, error) {
	exp := time.Now().Add(expires)

	claims := userClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: exp.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(j.secret))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (j *Jwt) VerifyUser(ctx context.Context, token string) (*users.User, error) {
	claims, err := j.getUserClaims(token)
	if err != nil {
		return nil, err
	}
	return claims.User, nil
}

func (j *Jwt) getUserClaims(token string) (*userClaims, error) {
	claims := &userClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(j.secret), nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

type Role string

type genericClaims struct {
	jwt.StandardClaims
	Role Role `json:"role"`
}

func (j *Jwt) Generic(role Role, expires time.Duration) (string, error) {
	exp := time.Now().Add(expires)
	claims := genericClaims{
		Role: role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exp.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(j.secret))
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func (j *Jwt) ValidateGeneric(ctx context.Context, token string) (Role, error) {
	claims := &genericClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return []byte(j.secret), nil
	})
	if err != nil {
		return "", err
	}
	return claims.Role, nil
}

func (j *Jwt) invalidatedKey(hash string) string {
	return fmt.Sprintf("tokens:invalidated:%s", hash)
}

func (j *Jwt) Expiry(ctx context.Context, token string) (time.Time, error) {
	claims := jwt.StandardClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return []byte(j.secret), nil
	})
	if err != nil {
		return time.Now(), fmt.Errorf("could not parse claims: %w", err)
	}

	if claims.ExpiresAt == 0 {
		return time.Now(), fmt.Errorf("no expiry set")
	}
	return time.Unix(claims.ExpiresAt, 0), nil
}
