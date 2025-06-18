package common

import "github.com/labstack/echo/v4"

type Handler[T any] func(c echo.Context, req T) error
