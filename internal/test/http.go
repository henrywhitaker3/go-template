package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

func Get(app *app.App, url string, apikey string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if apikey != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", apikey))
	}
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)

	return rec
}

func Post(t *testing.T, app *app.App, url string, body any, apikey string) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)

	return rec
}

func Put(t *testing.T, app *app.App, url string, body any, apikey string) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)

	return rec
}

func Patch(t *testing.T, app *app.App, url string, body any, apikey string) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)

	return rec
}

func Delete(t *testing.T, app *app.App, url string, body any, apikey string) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	app.Http.ServeHTTP(rec, req)

	return rec
}
