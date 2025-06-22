package common

import "github.com/labstack/echo/v4"

type Handler[Req any, Resp any] func(c echo.Context, req Req) (*Resp, error)

type ResponseKind struct {
	kind string
}

var (
	KindString = ResponseKind{"string"}
	KindJson   = ResponseKind{"json"}
)

type Metadata struct {
	Name         string
	Description  string
	Tag          string
	Code         int
	Method       string
	Path         string
	GenerateSpec bool
	Kind         ResponseKind
}
