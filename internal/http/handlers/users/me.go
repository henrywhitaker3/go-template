package users

import (
	"net/http"

	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/labstack/echo/v4"
)

type MeHandler struct{}

func NewMe() *MeHandler {
	return &MeHandler{}
}

func (m *MeHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		user, _ := common.GetUser(c.Request().Context())
		return c.JSON(http.StatusOK, user)
	}
}

func (m *MeHandler) Method() string {
	return http.MethodGet
}

func (m *MeHandler) Path() string {
	return "/auth/me"
}

func (m *MeHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
	}
}
