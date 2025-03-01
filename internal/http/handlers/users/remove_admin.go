package users

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type RemoveAdminHandler struct {
	users *users.Users
}

func NewRemoveAdmin(b *boiler.Boiler) *RemoveAdminHandler {
	return &RemoveAdminHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (m *RemoveAdminHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		req, ok := common.GetRequest[AdminRequest](c.Request().Context())
		if !ok {
			return common.ErrBadRequest
		}

		user, err := m.users.Get(c.Request().Context(), req.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: user not found", common.ErrValidation)
			}
			return common.Stack(err)
		}

		if err := m.users.RemoveAdmin(c.Request().Context(), user); err != nil {
			return common.Stack(err)
		}

		return c.NoContent(http.StatusAccepted)
	}
}

func (m *RemoveAdminHandler) Method() string {
	return http.MethodDelete
}

func (m *RemoveAdminHandler) Path() string {
	return "/auth/admin"
}

func (m *RemoveAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
		middleware.Admin(middleware.AdminOpts{
			Users: m.users,
		}),
		middleware.Bind[AdminRequest](),
	}
}
