package middleware

import (
	"errors"
	"log/slog"
	"time"

	"github.com/getsentry/sentry-go"
	sentryecho "github.com/getsentry/sentry-go/echo"
	pjwt "github.com/golang-jwt/jwt/v5"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type UserOpts struct {
	Jwt    *jwt.Jwt
	Config *config.Config
	Users  *users.Users
	Domain string
}

func User(opts UserOpts) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx, span := tracing.NewSpan(c.Request().Context(), "GetRequestUser")
			defer span.End()

			refresh := common.GetRefreshToken(c.Request())
			token := common.GetToken(c.Request())
			if token == "" && refresh == "" {
				return next(c)
			}

			user, err := opts.Jwt.VerifyUser(ctx, token)
			if err != nil {
				if !errors.Is(err, pjwt.ErrTokenExpired) && refresh == "" {
					return next(c)
				}

				// Token expired, check for refresh token and do things with it
				u, err := opts.Users.GetUserByRefreshToken(ctx, refresh)
				if err != nil {
					return next(c)
				}
				user = u
				token, err := opts.Jwt.NewForUser(u, time.Minute*5)
				if err != nil {
					return next(c)
				}
				newRefresh, err := opts.Users.RotateRefreshToken(ctx, refresh)
				if err != nil {
					slog.Error("failed to rotate user refresh token", "error", err)
				}
				common.SetUserAuthCookie(c, opts.Domain, token)
				common.SetUserRefreshTokenCookie(c, opts.Domain, newRefresh)
			}
			c.SetRequest(c.Request().WithContext(common.SetUser(c.Request().Context(), user)))

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
