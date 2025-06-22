package docs

import (
	"net/http"

	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/labstack/echo/v4"
)

type SchemaHandler struct {
	schema string
}

func NewSchema(schema string) *SchemaHandler {
	return &SchemaHandler{
		schema: schema,
	}
}

func (s *SchemaHandler) Handler() common.Handler[any, string] {
	return func(c echo.Context, req any) (*string, error) {
		c.Response().Header().Set(echo.HeaderContentType, "text/yaml")
		return &s.schema, nil
	}
}

func (s *SchemaHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:   "Openapi schema",
		Method: http.MethodGet,
		Path:   "/docs/schema.yaml",
		Kind:   common.KindString,
		Code:   http.StatusOK,
	}
}

func (s *SchemaHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{}
}
