package common

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/henrywhitaker3/ctxgen"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

var (
	ctxIdKey   = "request_id"
	traceIdKey = "trace_id"

	UserAuthCookie   = "user-auth"
	UserRefreshToken = "user-refresh"
)

func RequestID(c echo.Context) string {
	return c.Response().Header().Get(echo.HeaderXRequestID)
}

func SetContextID(ctx context.Context, id string) context.Context {
	return ctxgen.WithValue(ctx, ctxIdKey, id)
}

func ContextID(ctx context.Context) string {
	return ctxgen.Value[string](ctx, ctxIdKey)
}

func SetTraceID(ctx context.Context, id string) context.Context {
	return ctxgen.WithValue(ctx, traceIdKey, id)
}

func TraceID(ctx context.Context) string {
	return ctxgen.Value[string](ctx, traceIdKey)
}

func SetRequest[T any](ctx context.Context, req T) context.Context {
	return ctxgen.WithValue(ctx, "request", req)
}

func GetRequest[T any](ctx context.Context) (T, bool) {
	return ctxgen.ValueOk[T](ctx, "request")
}

func SetUser(ctx context.Context, user *users.User) context.Context {
	return ctxgen.WithValue(ctx, "user", user)
}

func GetUser(ctx context.Context) (*users.User, bool) {
	return ctxgen.ValueOk[*users.User](ctx, "user")
}

func GetToken(req *http.Request) string {
	header := req.Header.Get(echo.HeaderAuthorization)
	if header != "" {
		header = strings.Replace(header, "Bearer ", "", 1)
		return header
	}

	cookie, err := req.Cookie(UserAuthCookie)
	if err == nil {
		return cookie.Value
	}
	return ""
}

func GetRefreshToken(req *http.Request) string {
	cookie, err := req.Cookie(UserRefreshToken)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func SetUserAuthCookie(c echo.Context, domain string, token string) {
	c.SetCookie(&http.Cookie{
		Name:     UserAuthCookie,
		Value:    token,
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(time.Minute * 5),
	})
}

func SetUserRefreshTokenCookie(c echo.Context, domain string, token string) {
	c.SetCookie(&http.Cookie{
		Name:     UserRefreshToken,
		Value:    token,
		Path:     "/",
		Domain:   domain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(time.Hour * 24 * 30),
	})
}
