package http

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	sentryecho "github.com/getsentry/sentry-go/echo"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	mw "github.com/labstack/echo/v4/middleware"
)

type Http struct {
	e   *echo.Echo
	app *app.App
}

func New(app *app.App) *Http {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(mw.RequestID())
	if app.Config.Telemetry.Tracing.Enabled {
		e.Use(middleware.Tracing(app.Config.Telemetry.Tracing))
	}
	e.Use(middleware.User(app))
	if app.Config.Telemetry.Sentry.Enabled {
		e.Use(sentryecho.New(sentryecho.Options{
			Repanic: true,
		}))
	}
	e.Use(middleware.Zap(app.Config.LogLevel.Level()))
	e.Use(mw.Recover())
	e.Use(middleware.Logger())
	e.Use(mw.CORS())

	h := &Http{
		e:   e,
		app: app,
	}

	h.e.HTTPErrorHandler = h.handleError

	h.Register(users.NewLogin(app))
	h.Register(users.NewLogout(app))
	h.Register(users.NewRegister(app))
	h.Register(users.NewMe(app))
	h.Register(users.NewMakeAdmin(app))
	h.Register(users.NewRemoveAdmin(app))

	return h
}

func (h *Http) Start(ctx context.Context) error {
	logger.Logger(ctx).Infow("starting http server", "port", h.app.Config.Http.Port)
	if err := h.e.Start(fmt.Sprintf(":%d", h.app.Config.Http.Port)); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func (h *Http) Stop(ctx context.Context) error {
	logger.Logger(ctx).Info("stopping http server")
	return h.e.Shutdown(ctx)
}

func (h *Http) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.e.ServeHTTP(w, r)
}

type Handler interface {
	Handler() echo.HandlerFunc
	Method() string
	Path() string
	Middleware() []echo.MiddlewareFunc
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
				c.JSON(http.StatusUnprocessableEntity, newError("a record with the same details already exists"))
				return
			}
		}

		logger.Logger(c.Request().Context()).Errorw("unhandled error", "error", err)
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
