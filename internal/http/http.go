package http

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	sentryecho "github.com/getsentry/sentry-go/echo"
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	iusers "github.com/henrywhitaker3/go-template/internal/users"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	mw "github.com/labstack/echo/v4/middleware"
)

type Http struct {
	e *echo.Echo
	b *boiler.Boiler
}

func New(b *boiler.Boiler) *Http {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	conf := boiler.MustResolve[*config.Config](b)

	e.Use(mw.RequestID())
	if *conf.Telemetry.Tracing.Enabled {
		e.Use(middleware.Tracing(conf.Telemetry.Tracing))
	}
	if *conf.Telemetry.Metrics.Enabled {
		e.Use(middleware.Metrics(
			conf.Telemetry,
			boiler.MustResolve[*metrics.Metrics](b).Registry,
		))
	}
	e.Use(middleware.User(middleware.UserOpts{
		Config: conf,
		Jwt:    boiler.MustResolve[*jwt.Jwt](b),
		Users:  boiler.MustResolve[*iusers.Users](b),
		Domain: conf.Url,
	}))
	if *conf.Telemetry.Sentry.Enabled {
		e.Use(sentryecho.New(sentryecho.Options{
			Repanic: true,
		}))
	}
	e.Use(middleware.Zap(conf.LogLevel.Level()))
	e.Use(mw.Recover())
	e.Use(middleware.Logger())
	cors := mw.DefaultCORSConfig
	cors.AllowOrigins = conf.Http.AllowedOrigins
	cors.AllowCredentials = true
	e.Use(mw.CORSWithConfig(cors))

	h := &Http{
		e: e,
		b: b,
	}

	h.e.HTTPErrorHandler = h.handleError

	Register[users.LoginRequest, any](e, users.NewLogin(b))
	Register[any, any](e, users.NewLogout(b))
	Register[users.RegisterRequest, users.RegisterResponse](e, users.NewRegister(b))
	Register[any, any](e, users.NewMe())
	Register[users.AdminRequest, any](e, users.NewMakeAdmin(b))
	Register[users.AdminRequest, any](e, users.NewRemoveAdmin(b))
	Register[any, any](e, users.NewIsAdminHandler(b))

	return h
}

func (h *Http) Start(ctx context.Context) error {
	conf, err := boiler.Resolve[*config.Config](h.b)
	if err != nil {
		return err
	}
	slog.Info("starting http server", "port", conf.Http.Port)
	if err := h.e.Start(fmt.Sprintf(":%d", conf.Http.Port)); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func (h *Http) Stop(ctx context.Context) error {
	slog.Info("stopping http server")
	return h.e.Shutdown(ctx)
}

func (h *Http) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.e.ServeHTTP(w, r)
}

func (h *Http) Routes() []*echo.Route {
	return h.e.Routes()
}

type Handler interface {
	Handler() echo.HandlerFunc
	Method() string
	Path() string
	Middleware() []echo.MiddlewareFunc
}

type GenericHandler[Req any, Resp any] interface {
	Handler() common.Handler[Req]
	Method() string
	Path() string
	Middleware() []echo.MiddlewareFunc
}

func Register[Req any, Resp any](e *echo.Echo, handler GenericHandler[Req, Resp]) {
	var reg func(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route

	switch handler.Method() {
	case http.MethodGet:
		reg = e.GET
	case http.MethodPost:
		reg = e.POST
	case http.MethodPatch:
		reg = e.PATCH
	case http.MethodDelete:
		reg = e.DELETE
	case http.MethodPut:
		reg = e.PUT
	case http.MethodHead:
		reg = e.HEAD
	case http.MethodOptions:
		reg = e.OPTIONS
	default:
		panic("invalid http method registered")
	}

	mw := handler.Middleware()
	if len(mw) == 0 {
		// Add a empty middleware so []... doesn't add a nil item
		mw = []echo.MiddlewareFunc{
			func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					return next(c)
				}
			},
		}
	}

	reg(handler.Path(), wrapHandler[Req, Resp](handler), mw...)
}

func wrapHandler[Req any, Resp any](h GenericHandler[Req, Resp]) echo.HandlerFunc {
	handler := h.Handler()
	return func(c echo.Context) error {
		_, span := tracing.NewSpan(c.Request().Context(), "BindRequest")
		defer span.End()

		var req Req
		if err := c.Bind(&req); err != nil {
			slog.Debug("failed to bind request", "error", err)
			return common.ErrBadRequest
		}
		// TODO: validation
		span.End()

		return handler(c, req)
	}
}

func (h *Http) Register(handler Handler) {
	var reg func(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route

	switch handler.Method() {
	case http.MethodGet:
		reg = h.e.GET
	case http.MethodPost:
		reg = h.e.POST
	case http.MethodPatch:
		reg = h.e.PATCH
	case http.MethodDelete:
		reg = h.e.DELETE
	case http.MethodPut:
		reg = h.e.PUT
	case http.MethodHead:
		reg = h.e.HEAD
	case http.MethodOptions:
		reg = h.e.OPTIONS
	default:
		panic("invalid http method registered")
	}

	mw := handler.Middleware()
	if len(mw) == 0 {
		// Add a empty middleware so []... doesn't add a nil item
		mw = []echo.MiddlewareFunc{
			func(next echo.HandlerFunc) echo.HandlerFunc {
				return func(c echo.Context) error {
					return next(c)
				}
			},
		}
	}

	reg(handler.Path(), handler.Handler(), mw...)
}

func (h *Http) handleError(err error, c echo.Context) {
	switch true {
	case errors.Is(err, sql.ErrNoRows):
		c.JSON(http.StatusNotFound, newError("not found"))

	case errors.Is(err, common.ErrValidation):
		c.JSON(http.StatusUnprocessableEntity, newError(err.Error()))

	case errors.Is(err, common.ErrBadRequest):
		c.JSON(http.StatusBadRequest, newError(err.Error()))

	case errors.Is(err, common.ErrUnauth):
		c.JSON(http.StatusUnauthorized, newError(err.Error()))

	case errors.Is(err, common.ErrForbidden):
		c.JSON(http.StatusForbidden, newError("fobidden"))

	case errors.Is(err, common.ErrNotFound):
		c.JSON(http.StatusNotFound, newError("not found"))

	case h.isHttpError(err):
		herr := err.(*echo.HTTPError)
		c.JSON(herr.Code, herr)

	default:
		pgErr, ok := h.asPgError(err)
		if ok {
			switch pgErr.Code {
			// Unique constraint violation
			case "23505":
				c.JSON(
					http.StatusUnprocessableEntity,
					newError("a record with the same details already exists"),
				)
				return
			}
		}

		slog.ErrorContext(c.Request().Context(), "unhandled error", "error", err)
		if hub := sentryecho.GetHubFromContext(c); hub != nil {
			hub.CaptureException(err)
		}
		h.e.DefaultHTTPErrorHandler(err, c)
	}
}

type errorJson struct {
	Message string `json:"message"`
}

func newError(msg string) errorJson {
	return errorJson{Message: msg}
}

func (sh *Http) isHttpError(err error) bool {
	switch err.(type) {
	case *echo.HTTPError:
		return true
	default:
		return false
	}
}

func (h *Http) asPgError(err error) (*pgconn.PgError, bool) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg, true
	}
	return nil, false
}
