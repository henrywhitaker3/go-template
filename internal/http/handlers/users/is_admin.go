package users

import (
	"net/http"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type IsAdminHandler struct {
	users *users.Users
}

func NewIsAdminHandler(b *boiler.Boiler) *IsAdminHandler {
	return &IsAdminHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (i *IsAdminHandler) Handler() common.Handler[any, any] {
	return func(c echo.Context, _ any) (*any, error) {
		ctx, span := tracing.NewSpan(c.Request().Context(), "IsAdmin")
		defer span.End()

		user, ok := common.GetUser(ctx)
		if !ok {
			return nil, common.ErrUnauth
		}

		user, err := i.users.Get(ctx, user.ID)
		if err != nil {
			return nil, common.Stack(err)
		}

		if user.Admin {
			return nil, nil
		}

		return nil, common.ErrForbidden
	}
}

func (m *IsAdminHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Check if you are an admin",
		Tag:          "Auth",
		Code:         http.StatusOK,
		Method:       http.MethodGet,
		Path:         "/auth/admin",
		GenerateSpec: true,
	}
}

func (i *IsAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
	}
}
