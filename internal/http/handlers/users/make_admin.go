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
	"github.com/henrywhitaker3/go-template/internal/uuid"
	"github.com/labstack/echo/v4"
)

type AdminRequest struct {
	ID uuid.UUID `json:"id"`
}

func (a AdminRequest) Validate() error {
	return nil
}

type MakeAdminHandler struct {
	users *users.Users
}

func NewMakeAdmin(b *boiler.Boiler) *MakeAdminHandler {
	return &MakeAdminHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (m *MakeAdminHandler) Handler() common.Handler[AdminRequest] {
	return func(c echo.Context, req AdminRequest) error {
		user, err := m.users.Get(c.Request().Context(), req.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: user not found", common.ErrValidation)
			}
			return common.Stack(err)
		}

		if err := m.users.MakeAdmin(c.Request().Context(), user); err != nil {
			return common.Stack(err)
		}

		return c.NoContent(http.StatusAccepted)
	}
}

func (m *MakeAdminHandler) Method() string {
	return http.MethodPost
}

func (m *MakeAdminHandler) Path() string {
	return "/auth/admin"
}

func (m *MakeAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
		middleware.Admin(middleware.AdminOpts{
			Users: m.users,
		}),
	}
}
