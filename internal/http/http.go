package http

import (
	"log/slog"

	sentryecho "github.com/getsentry/sentry-go/echo"
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	iusers "github.com/henrywhitaker3/go-template/internal/users"
	whttp "github.com/henrywhitaker3/windowframe/http"
	wmiddleware "github.com/henrywhitaker3/windowframe/http/middleware"
	"github.com/labstack/echo/v4"
	mw "github.com/labstack/echo/v4/middleware"
)

func New(b *boiler.Boiler) *whttp.HTTP {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	conf := boiler.MustResolve[*config.Config](b)
	h := whttp.New(whttp.HTTPOpts{
		Port:           conf.Http.Port,
		ServiceName:    conf.Name,
		Version:        string(b.Version()),
		PublicURL:      conf.Url,
		OpenapiEnabled: true,
		Logger:         slog.With("component", "http"),
	})

	h.Use(mw.RequestID())
	if *conf.Telemetry.Tracing.Enabled {
		h.Use(wmiddleware.Tracing(conf.Telemetry.Tracing.ServiceName))
	}
	if *conf.Telemetry.Metrics.Enabled {
		h.Use(wmiddleware.Metrics(
			conf.Telemetry.Tracing.ServiceName,
			boiler.MustResolve[*metrics.Metrics](b).Registry,
		))
	}
	h.Use(middleware.User(middleware.UserOpts{
		Config: conf,
		Jwt:    boiler.MustResolve[*jwt.Jwt](b),
		Users:  boiler.MustResolve[*iusers.Users](b),
		Domain: conf.Url,
	}))
	if *conf.Telemetry.Sentry.Enabled {
		h.Use(sentryecho.New(sentryecho.Options{
			Repanic: true,
		}))
	}
	h.Use(wmiddleware.Zap(conf.LogLevel.Level()))
	h.Use(mw.Recover())
	h.Use(wmiddleware.Logger())
	cors := mw.DefaultCORSConfig
	cors.AllowOrigins = conf.Http.AllowedOrigins
	cors.AllowCredentials = true
	h.Use(mw.CORSWithConfig(cors))

	whttp.Register(h, users.NewLogin(b))
	whttp.Register(h, users.NewLogout(b))
	whttp.Register(h, users.NewRegister(b))
	whttp.Register(h, users.NewMe())
	whttp.Register(h, users.NewMakeAdmin(b))
	whttp.Register(h, users.NewRemoveAdmin(b))
	whttp.Register(h, users.NewIsAdminHandler(b))
	return h
}
