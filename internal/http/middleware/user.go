package middleware

import (
	"github.com/getsentry/sentry-go"
	sentryecho "github.com/getsentry/sentry-go/echo"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/labstack/echo/v4"
)

type UserOpts struct {
	Jwt    *jwt.Jwt
	Config *config.Config
}

func User(opts UserOpts) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracing.NewSpan(c.Request().Context(), "GetRequestUser")
			defer span.End()

			token := common.GetToken(c.Request())
			if token == "" {
				return next(c)
			}

			user, err := opts.Jwt.VerifyUser(ctx, token)
			if err == nil {
				c.SetRequest(c.Request().WithContext(common.SetUser(c.Request().Context(), user)))
			}

			if user != nil {
				if *opts.Config.Telemetry.Sentry.Enabled {
					if hub := sentryecho.GetHubFromContext(c); hub != nil {
						hub.Scope().SetUser(sentry.User{
							ID:    user.ID.String(),
							Email: user.Email,
							Name:  user.Name,
						})
					}
				}
				if *opts.Config.Telemetry.Tracing.Enabled {
					tracing.AddString(c.Request().Context(), "user_id", user.ID.String())
					tracing.AddString(c.Request().Context(), "request_id", common.RequestID(c))
				}
			}
			span.End()

			// TODO: add handling for cookies

			return next(c)
		}
	}
}
