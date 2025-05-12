package middleware

import (
	"strconv"
	"time"

	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/labstack/echo/v4"
)

func Logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			ctx, span := tracing.NewSpan(c.Request().Context(), "LogRequest")
			defer span.End()
			dur := time.Since(start)
			logger := logger.Logger(ctx).
				With(
					"remote_ip", c.RealIP(),
					"host", c.Request().Host,
					"uri", c.Request().RequestURI,
					"method", c.Request().Method,
					"user_agent", c.Request().UserAgent(),
					"status", c.Response().Status,
					"latency", dur.Nanoseconds(),
					"latency_human", dur.String(),
					"bytes_in", bytesIn(c),
					"bytes_out", bytesOut(c),
				)
			if err != nil {
				c.Error(err)
				if c.Response().Status >= 500 {
					logger = logger.With("error", err.Error())
				}
			}
			logger.Info("request")
			return nil
		}
	}
}

func bytesIn(c echo.Context) string {
	cl := c.Request().Header.Get(echo.HeaderContentLength)
	if cl == "" {
		cl = "0"
	}
	return cl
}

func bytesOut(c echo.Context) string {
	return strconv.FormatInt(c.Response().Size, 10)
}
