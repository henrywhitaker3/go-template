package middleware

import (
	"log/slog"

	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/labstack/echo/v4"
)

func Zap(level slog.Level) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			id := common.RequestID(c)
			if id != "" {
				ctx = common.SetContextID(ctx, id)
			}

			if traceId := tracing.TraceID(ctx); traceId != "" {
				ctx = common.SetTraceID(ctx, traceId)
			}

			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	}
}
