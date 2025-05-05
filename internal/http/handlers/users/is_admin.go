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

type IsAdminHandler struct {
	users *users.Users
}

func NewIsAdminHandler(b *boiler.Boiler) *IsAdminHandler {
	return &IsAdminHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (i *IsAdminHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, span := tracing.NewSpan(c.Request().Context(), "IsAdmin")
		defer span.End()

		user, ok := common.GetUser(ctx)
		if !ok {
			return common.ErrUnauth
		}

		user, err := i.users.Get(ctx, user.ID)
		if err != nil {
			return common.Stack(err)
		}

		if user.Admin {
			return c.NoContent(http.StatusOK)
		}

		return common.ErrForbidden
	}
}

func (i *IsAdminHandler) Method() string {
	return http.MethodGet
}

func (i *IsAdminHandler) Path() string {
	return "/auth/admin"
}

func (i *IsAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
	}
}
