package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/henrywhitaker3/go-template/internal/crypto"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/redis/rueidis"
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
	redis  rueidis.Client
}

func New(secret string, redis rueidis.Client) *Jwt {
	return &Jwt{
		secret: secret,
		redis:  redis,
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
	if err := j.isInvalidated(ctx, token); err != nil {
		return nil, err
	}
	claims, err := j.getUserClaims(token)
	if err != nil {
		return nil, err
	}
	return claims.User, nil
}

func (j *Jwt) isInvalidated(ctx context.Context, token string) error {
	hash := crypto.Sum(token)

	// Check if the token has been invalidated first
	cmd := j.redis.B().Get().Key(j.invalidatedKey(hash)).Build()
	res := j.redis.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		if !errors.Is(err, rueidis.Nil) {
			return err
		}
		return nil
	}
	return ErrInvalidated
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

func (j *Jwt) InvalidateToken(ctx context.Context, token string) error {
	claims, err := j.getUserClaims(token)
	if err != nil {
		return err
	}

	expires := time.Unix(claims.ExpiresAt, 0)
	remaining := time.Until(expires)

	cmd := j.redis.B().
		Set().
		Key(j.invalidatedKey(crypto.Sum(token))).
		Value("true").
		Ex(remaining).
		Build()
	res := j.redis.Do(ctx, cmd)
	return res.Error()
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
	if err := j.isInvalidated(ctx, token); err != nil {
		return "", err
	}
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
	if err := j.isInvalidated(ctx, token); err != nil {
		return time.Now(), err
	}
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
