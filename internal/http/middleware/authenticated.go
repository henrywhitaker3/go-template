package middleware

import (
	"github.com/henrywhitaker3/ctxgen"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/windowframe/http/common"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/labstack/echo/v4"
)

func Authenticated() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracing.NewSpan(c.Request().Context(), "AuthCheck")
			defer span.End()
			if _, ok := ctxgen.ValueOk[*users.User](ctx, "user"); !ok {
				return common.Stack(common.ErrUnauth)
			}
			span.End()
			return next(c)
		}
	}
}
