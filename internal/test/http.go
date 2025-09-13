package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/henrywhitaker3/boiler"
	whttp "github.com/henrywhitaker3/windowframe/http"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func Get(
	t *testing.T,
	b *boiler.Boiler,
	url string,
	apikey string,
	headers ...map[string]string,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	rec := httptest.NewRecorder()

	if len(headers) > 0 {
		for _, c := range headers {
			for key, val := range c {
				req.Header.Set(key, val)
			}
		}
	}

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)

	srv.ServeHTTP(rec, req)

	return rec
}

func Post(
	t *testing.T,
	b *boiler.Boiler,
	url string,
	body any,
	apikey string,
	headers ...map[string]string,
) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		by, err := json.Marshal(body)
		require.Nil(t, err)
		reader = bytes.NewReader(by)
	}

	req := httptest.NewRequest(http.MethodPost, url, reader)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	req.Header.Set("Content-type", echo.MIMEApplicationJSON)

	if len(headers) > 0 {
		for _, c := range headers {
			for key, val := range c {
				req.Header.Set(key, val)
			}
		}
	}

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	return rec
}

func Put(
	t *testing.T,
	b *boiler.Boiler,
	url string,
	body any,
	apikey string,
	headers ...map[string]string,
) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		by, err := json.Marshal(body)
		require.Nil(t, err)
		reader = bytes.NewReader(by)
	}

	req := httptest.NewRequest(http.MethodPut, url, reader)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	req.Header.Set("Content-type", echo.MIMEApplicationJSON)

	if len(headers) > 0 {
		for _, c := range headers {
			for key, val := range c {
				req.Header.Set(key, val)
			}
		}
	}

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	return rec
}

func Patch(
	t *testing.T,
	b *boiler.Boiler,
	url string,
	body any,
	apikey string,
	headers ...map[string]string,
) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		by, err := json.Marshal(body)
		require.Nil(t, err)
		reader = bytes.NewReader(by)
	}

	req := httptest.NewRequest(http.MethodPatch, url, reader)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	req.Header.Set("Content-type", echo.MIMEApplicationJSON)

	if len(headers) > 0 {
		for _, c := range headers {
			for key, val := range c {
				req.Header.Set(key, val)
			}
		}
	}

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	return rec
}

func Delete(
	t *testing.T,
	b *boiler.Boiler,
	url string,
	body any,
	apikey string,
	headers ...map[string]string,
) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		by, err := json.Marshal(body)
		require.Nil(t, err)
		reader = bytes.NewReader(by)
	}

	req := httptest.NewRequest(http.MethodDelete, url, reader)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	req.Header.Set("Content-type", echo.MIMEApplicationJSON)

	if len(headers) > 0 {
		for _, c := range headers {
			for key, val := range c {
				req.Header.Set(key, val)
			}
		}
	}

	srv, err := boiler.Resolve[*whttp.HTTP](b)
	require.Nil(t, err)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	return rec
}

func ParseCookies(t *testing.T, headers http.Header) map[string]string {
	cookies, ok := headers["Set-Cookie"]
	require.True(t, ok)

	out := map[string]string{}
	for _, c := range cookies {
		valkey := strings.Split(strings.Split(c, "; ")[0], "=")
		out[valkey[0]] = valkey[1]
	}
	return out
}
