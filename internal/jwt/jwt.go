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
	hash := crypto.Sum(token)

	// Check if the token has been invalidated first
	cmd := j.redis.B().Get().Key(j.invalidatedKey(hash)).Build()
	res := j.redis.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		if !errors.Is(err, rueidis.Nil) {
			return nil, err
		}
	} else {
		return nil, ErrInvalidated
	}

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

func (j *Jwt) InvalidateUser(ctx context.Context, token string) error {
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

func (j *Jwt) invalidatedKey(hash string) string {
	return fmt.Sprintf("tokens:invalidated:%s", hash)
}
