package users

import (
	"net/http"

	"github.com/henrywhitaker3/ctxgen"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/windowframe/http/common"
	"github.com/labstack/echo/v4"
)

type MeHandler struct{}

func NewMe() *MeHandler {
	return &MeHandler{}
}

func (m *MeHandler) Handler() common.Handler[any, users.User] {
	return func(c echo.Context, _ any) (*users.User, error) {
		user, _ := ctxgen.ValueOk[*users.User](c.Request().Context(), "user")
		return user, nil
	}
}

func (m *MeHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Me",
		Description:  "Get the current aithenticated user",
		Tag:          "Auth",
		Code:         http.StatusOK,
		Method:       http.MethodGet,
		Path:         "/auth/me",
		GenerateSpec: true,
	}
}

func (m *MeHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
	}
}
