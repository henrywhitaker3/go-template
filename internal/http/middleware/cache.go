package middleware

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/rueidis"
)

type Route struct {
	Method string
	Path   string
}

type Cacher interface {
	// A list of http routes that will invalidate the cached response
	InvalidatedBy(c echo.Context) []Route
}

type storedRequest struct {
	Code    int         `json:"code"`
	Body    string      `json:"body"`
	Headers http.Header `json:"headers"`
}

// A middleware that caches the response body/type/status code
// This will cached based on the method/path of the request, not suitable
// for user-scoped responses.
//
// This middleware will check for the existence of a cached response, and return that
// if it exists in redis - else it will handle the request and store the response in redis.
// The route key is then added to various sets (the Cacher's InvalidatedBy() routes).
// See Invalidate() middleware for cache invalidation.
func Cache(redis rueidis.Client, cacher Cacher, dur time.Duration) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := routeKey(Route{Method: c.Request().Method, Path: c.Request().URL.Path})
			if key == "" {
				return next(c)
			}

			ctx, span := tracing.NewSpan(c.Request().Context(), "RetrieveCachedResponse")
			defer span.End()

			registerInvalidations(ctx, redis, cacher.InvalidatedBy(c), key)

			stored, err := getStoredRequest(ctx, redis, key)
			if err != nil {
				if !errors.Is(err, rueidis.Nil) {
					return common.Stack(err)
				}
			} else {
				for key, val := range stored.Headers {
					if len(val) > 0 {
						c.Response().Header().Set(key, val[0])
					}
				}
				mime := echo.MIMEApplicationJSON
				if val, ok := stored.Headers[echo.HeaderContentType]; ok {
					if len(val) > 0 {
						mime = val[0]
					}
				}
				return c.Blob(stored.Code, mime, []byte(stored.Body))
			}
			span.End()

			ctx, span = tracing.NewSpan(c.Request().Context(), "StoreCachedRequest")
			defer span.End()

			return storeRequest(c, redis, key, dur, next)
		}
	}
}

func storeRequest(c echo.Context, redis rueidis.Client, key string, dur time.Duration, next echo.HandlerFunc) error {
	logger.Logger(c.Request().Context()).Debugw("caching response", "key", key)
	var body []byte
	var code int
	var headers http.Header
	dump := middleware.BodyDumpWithConfig(middleware.BodyDumpConfig{
		Handler: func(ctx echo.Context, _, resp []byte) {
			body = resp
			code = c.Response().Status
			headers = c.Response().Header()
		},
	})
	hErr := dump(next)(c)
	if hErr != nil {
		return hErr
	}

	save := storedRequest{
		Code:    code,
		Body:    string(body),
		Headers: headers,
	}
	by, err := json.Marshal(save)
	if err != nil {
		return common.Stack(err)
	}
	cmd := redis.B().Setex().Key(key).Seconds(int64(dur.Seconds())).Value(string(by)).Build()
	if res := redis.Do(c.Request().Context(), cmd); res.Error() != nil {
		return common.Stack(res.Error())
	}
	return hErr
}

func getStoredRequest(ctx context.Context, redis rueidis.Client, key string) (*storedRequest, error) {
	logger.Logger(ctx).With("key", key).Debug("checking if there's a cached response")
	cached := redis.B().Get().Key(key).Build()
	res := redis.Do(ctx, cached)
	if err := res.Error(); err != nil {
		return nil, common.Stack(err)
	}

	stored := &storedRequest{}
	by, err := res.AsBytes()
	if err != nil {
		return nil, common.Stack(err)
	}
	if err := json.Unmarshal(by, stored); err != nil {
		return nil, common.Stack(err)
	}
	return stored, nil
}

func routeKey(route Route) string {
	return fmt.Sprintf("cached:%s:%s", route.Method, route.Path)
}

func invalidatesKey(route Route) string {
	return fmt.Sprintf("cached:invalidates:%s:%s", route.Method, route.Path)
}

func registerInvalidations(ctx context.Context, redis rueidis.Client, routes []Route, key string) {
	logger := logger.Logger(ctx).With("invalidates", key)
	for _, r := range routes {
		route := invalidatesKey(r)
		logger.Debugw("registering invalidation", "route", route)
		cmd := redis.B().Sadd().Key(route).Member(key).Build()
		redis.Do(ctx, cmd)
	}
}

// When a route has the Cache middleware, it can register routes that will invalidate their cached
// response. This middleware will check any registered invalidations in it's own invalidates set
// and delete any stored keys in redis associated with it.
func Invalidate(redis rueidis.Client) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := invalidatesKey(Route{Method: c.Request().Method, Path: c.Request().URL.Path})

			ctx, span := tracing.NewSpan(c.Request().Context(), "InvalidateRouteCache")
			defer span.End()

			logger := logger.Logger(ctx).With("key", key)
			logger.Debugw("invalidating cached responses")

			if err := invalidateCache(ctx, redis, key); err != nil {
				logger.Errorw("failed to invalidate cached routes", "error", err)
				// This is not fatal, let it carry on
			}

			return next(c)
		}
	}
}

func invalidateCache(ctx context.Context, redis rueidis.Client, key string) error {
	cmd := redis.B().Smembers().Key(key).Build()
	res := redis.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		if !errors.Is(err, rueidis.Nil) {
			return common.Stack(err)
		}
		return nil
	}
	members, err := res.AsStrSlice()
	if err != nil {
		return common.Wrap(err, "failed to cast smembers to str slice")
	}

	if len(members) == 0 {
		return nil
	}

	cmd = redis.B().Del().Key(members...).Build()
	res = redis.Do(ctx, cmd)
	return res.Error()
}
