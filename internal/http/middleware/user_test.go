package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestItAuthenticatesByHeaderToken(t *testing.T) {
	app, cancel := test.App(t)
	defer cancel()

	user, _ := test.User(t, app)
	token, err := app.Jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestItAuthenticatesByHeaderCookie(t *testing.T) {
	app, cancel := test.App(t)
	defer cancel()

	user, _ := test.User(t, app)
	token, err := app.Jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     "auth",
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}
