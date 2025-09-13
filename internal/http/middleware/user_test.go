package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
	whttp "github.com/henrywhitaker3/windowframe/http"
	"github.com/henrywhitaker3/windowframe/http/common"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func TestItAuthenticatesByHeaderToken(t *testing.T) {
	b := test.Boiler(t)

	srv, err := boiler.Resolve[*whttp.HTTP](b)
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

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)
	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	user, _ := test.User(t, b)
	token, err := jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserAuthCookie,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestItRefreshesAnExpiredTokenWithValidRefreshToken(t *testing.T) {
	b := test.Boiler(t)

	srv := boiler.MustResolve[*whttp.HTTP](b)
	jwt := boiler.MustResolve[*jwt.Jwt](b)
	users := boiler.MustResolve[*users.Users](b)

	user, _ := test.User(t, b)
	token, err := jwt.NewForUser(user, time.Second)
	require.Nil(t, err)
	refresh, err := users.CreateRefreshToken(context.Background(), user.ID, time.Hour)
	require.Nil(t, err)

	time.Sleep(time.Second * 2)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserAuthCookie,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserAuthCookie,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    refresh,
		Secure:   true,
		HttpOnly: true,
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	headers := rec.Header()
	_, ok := headers["Set-Cookie"]
	require.True(t, ok)
}

func TestItRefreshesWithNoTokenButValidRefresh(t *testing.T) {
	b := test.Boiler(t)

	srv := boiler.MustResolve[*whttp.HTTP](b)
	users := boiler.MustResolve[*users.Users](b)

	user, _ := test.User(t, b)
	refresh, err := users.CreateRefreshToken(context.Background(), user.ID, time.Hour)
	require.Nil(t, err)

	time.Sleep(time.Second * 2)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    refresh,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	headers := rec.Header()
	_, ok := headers["Set-Cookie"]
	require.True(t, ok)
}

func TestItRotatesRefreshTokens(t *testing.T) {
	b := test.Boiler(t)

	srv := boiler.MustResolve[*whttp.HTTP](b)
	users := boiler.MustResolve[*users.Users](b)

	user, _ := test.User(t, b)
	refresh, err := users.CreateRefreshToken(context.Background(), user.ID, time.Hour)
	require.Nil(t, err)

	time.Sleep(time.Second * 2)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    refresh,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	cookies := test.ParseCookies(t, rec.Header())
	require.Contains(t, cookies, common.UserAuthCookie)
	require.Contains(t, cookies, common.UserRefreshToken)

	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    refresh,
		Secure:   true,
		HttpOnly: true,
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    cookies[common.UserRefreshToken],
		Secure:   true,
		HttpOnly: true,
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestItDoesntRefreshAnExpiredTokenWithInvalidRefreshToken(t *testing.T) {
	b := test.Boiler(t)

	srv := boiler.MustResolve[*whttp.HTTP](b)
	jwt := boiler.MustResolve[*jwt.Jwt](b)

	user, _ := test.User(t, b)
	token, err := jwt.NewForUser(user, time.Second)
	require.Nil(t, err)

	time.Sleep(time.Second * 2)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserAuthCookie,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.AddCookie(&http.Cookie{
		Name:     common.UserAuthCookie,
		Value:    token,
		Secure:   true,
		HttpOnly: true,
	})
	req.AddCookie(&http.Cookie{
		Name:     common.UserRefreshToken,
		Value:    "bongo",
		Secure:   true,
		HttpOnly: true,
	})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}
