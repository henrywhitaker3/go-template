package middleware

import (
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/labstack/echo/v4"
)

func Authenticated() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracing.NewSpan(c.Request().Context(), "AuthCheck")
			defer span.End()
			_, ok := common.GetUser(ctx)
			if !ok {
				return common.Stack(common.ErrUnauth)
			}
			span.End()
			return next(c)
		}
	}
}
