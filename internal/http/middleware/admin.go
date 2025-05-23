package middleware

import (
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type AdminOpts struct {
	Users *users.Users
}

func Admin(opts AdminOpts) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracing.NewSpan(c.Request().Context(), "AdminCheck")
			defer span.End()

			user, ok := common.GetUser(ctx)
			if !ok {
				return common.Stack(common.ErrUnauth)
			}
			user, err := opts.Users.Get(ctx, user.ID)
			if err != nil {
				return common.Stack(err)
			}
			if !user.Admin {
				return common.Stack(common.ErrForbidden)
			}
			span.End()

			return next(c)
		}
	}
}
