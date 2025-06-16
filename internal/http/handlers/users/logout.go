package users

import (
	"net/http"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type LogoutHandler struct {
	users *users.Users
}

func NewLogout(b *boiler.Boiler) *LogoutHandler {
	return &LogoutHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (l *LogoutHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, span := tracing.NewSpan(c.Request().Context(), "Logout")
		defer span.End()

		if refresh := common.GetRefreshToken(c.Request()); refresh != "" {
			if err := l.users.DeleteRefreshToken(ctx, refresh); err != nil {
				return common.Stack(err)
			}
		}
		return c.NoContent(http.StatusAccepted)
	}
}

func (l *LogoutHandler) Method() string {
	return http.MethodPost
}

func (l *LogoutHandler) Path() string {
	return "/auth/logout"
}

func (l *LogoutHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
	}
}
