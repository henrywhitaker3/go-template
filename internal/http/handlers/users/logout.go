package users

import (
	"net/http"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/labstack/echo/v4"
)

type LogoutHandler struct {
	jwt *jwt.Jwt
}

func NewLogout(b *boiler.Boiler) *LogoutHandler {
	return &LogoutHandler{
		jwt: boiler.MustResolve[*jwt.Jwt](b),
	}
}

func (l *LogoutHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		// token := common.GetToken(c.Request())
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
