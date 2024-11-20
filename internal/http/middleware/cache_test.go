package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

type emptyCacher struct {
	hits int
}

func (e *emptyCacher) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		e.hits++
		return c.String(http.StatusOK, fmt.Sprintf("%d", e.hits))
	}
}

func (e emptyCacher) InvalidatedBy(c echo.Context) []middleware.Route {
	return []middleware.Route{
		{
			Method: http.MethodGet,
			Path:   "/invalidate",
		},
	}
}

func TestItCachesMiddleware(t *testing.T) {
	app, cancel := test.App(t)
	defer cancel()

	handler := &emptyCacher{}

	e := echo.New()
	e.GET("/no-cache", handler.Handler())
	e.GET("/", handler.Handler(), middleware.Cache(app.Redis, emptyCacher{}, time.Minute))

	do := func(expected int, cache bool) *httptest.ResponseRecorder {
		url := "/"
		if !cache {
			url = "/no-cache"
		}
		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, rec.Body.String(), fmt.Sprintf("%d", expected))
		return rec
	}

	do(1, false)
	// time.Sleep(time.Millisecond * 100)
	do(2, true)
	// time.Sleep(time.Millisecond * 100)
	do(2, true)
}

type invalidatesEmptyCache struct{}

func (i invalidatesEmptyCache) InvalidatedBy(c echo.Context) []middleware.Route {
	return []middleware.Route{
		{
			Method: http.MethodGet,
			Path:   "/",
		},
	}
}

func (i invalidatesEmptyCache) Stores(c echo.Context) string {
	return ""
}

func (i invalidatesEmptyCache) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}
}

func TestItInvalidatesOtherRoutes(t *testing.T) {
	app, cancel := test.App(t, true)
	defer cancel()

	cached := &emptyCacher{}
	invalid := &invalidatesEmptyCache{}

	e := echo.New()
	e.Use(middleware.Invalidate(app.Redis))
	e.GET("/", cached.Handler(), middleware.Cache(app.Redis, cached, time.Minute))
	e.GET("/invalidate", invalid.Handler())

	do := func(expected int, invalidate bool) *httptest.ResponseRecorder {
		url := "/"
		if invalidate {
			url = "/invalidate"
		}
		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		if !invalidate {
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, rec.Body.String(), fmt.Sprintf("%d", expected))
		}
		return rec
	}

	do(1, false)
	// time.Sleep(time.Millisecond * 100)
	do(1, false)
	// time.Sleep(time.Millisecond * 100)
	do(1, true)
	// time.Sleep(time.Millisecond * 100)
	do(2, false)
}
