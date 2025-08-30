package users

import (
	"net/http"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/windowframe/tracing"
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

func (l *LogoutHandler) Handler() common.Handler[any, any] {
	return func(c echo.Context, _ any) (*any, error) {
		ctx, span := tracing.NewSpan(c.Request().Context(), "Logout")
		defer span.End()

		if refresh := common.GetRefreshToken(c.Request()); refresh != "" {
			if err := l.users.DeleteRefreshToken(ctx, refresh); err != nil {
				return nil, common.Stack(err)
			}
		}

		return nil, nil
	}
}

func (m *LogoutHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Logout",
		Description:  "Logout and invalidate refresh token",
		Tag:          "Auth",
		Code:         http.StatusAccepted,
		Method:       http.MethodPost,
		Path:         "/auth/logout",
		GenerateSpec: true,
	}
}

func (l *LogoutHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{}
}
