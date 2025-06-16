package users_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/stretchr/testify/require"
)

func TestItLogsInAUser(t *testing.T) {
	b := test.Boiler(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	user, password := test.User(t, b)

	rec := test.Post(t, b, "/auth/login", users.LoginRequest{
		Email:    user.Email,
		Password: password,
	}, "")

	require.Equal(t, http.StatusOK, rec.Code)

	cookies := parseCookies(t, rec.Header())

	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	tuser, err := jwt.VerifyUser(ctx, cookies[common.UserAuthCookie])
	require.Nil(t, err)
	require.Equal(t, user.ID, tuser.ID)
}

func parseCookies(t *testing.T, headers http.Header) map[string]string {
	cookies, ok := headers["Set-Cookie"]
	require.True(t, ok)

	out := map[string]string{}
	for _, c := range cookies {
		valkey := strings.Split(strings.Split(c, "; ")[0], "=")
		out[valkey[0]] = valkey[1]
	}
	return out
}

func TestItErrorsWhenIncorrectPassword(t *testing.T) {
	b := test.Boiler(t)

	user, _ := test.User(t, b)

	rec := test.Post(t, b, "/auth/login", users.LoginRequest{
		Email:    user.Email,
		Password: test.Sentence(5),
	}, "")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestItErrorsWhenIncorrectEmail(t *testing.T) {
	b := test.Boiler(t)

	rec := test.Post(t, b, "/auth/login", users.LoginRequest{
		Email:    test.Email(),
		Password: test.Sentence(5),
	}, "")

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
