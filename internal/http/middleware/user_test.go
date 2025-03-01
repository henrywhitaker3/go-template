package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	ohttp "github.com/henrywhitaker3/go-template/internal/http"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestItAuthenticatesByHeaderToken(t *testing.T) {
	b := test.Boiler(t)

	srv, err := boiler.Resolve[*ohttp.Http](b)
	require.Nil(t, err)
	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	user, _ := test.User(t, b)
	token, err := jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestItAuthenticatesByHeaderCookie(t *testing.T) {
	b := test.Boiler(t)

	srv, err := boiler.Resolve[*ohttp.Http](b)
	require.Nil(t, err)
	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	user, _ := test.User(t, b)
	token, err := jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     "auth",
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
