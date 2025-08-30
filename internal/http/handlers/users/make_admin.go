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
	"github.com/henrywhitaker3/windowframe/uuid"
	"github.com/labstack/echo/v4"
)

type AdminRequest struct {
	ID uuid.UUID `json:"id" validate:"required"`
}

type MakeAdminHandler struct {
	users *users.Users
}

func NewMakeAdmin(b *boiler.Boiler) *MakeAdminHandler {
	return &MakeAdminHandler{
		users: boiler.MustResolve[*users.Users](b),
	}
}

func (m *MakeAdminHandler) Handler() common.Handler[AdminRequest, any] {
	return func(c echo.Context, req AdminRequest) (*any, error) {
		user, err := m.users.Get(c.Request().Context(), req.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: user not found", common.ErrValidation)
			}
			return nil, common.Stack(err)
		}

		if err := m.users.MakeAdmin(c.Request().Context(), user); err != nil {
			return nil, common.Stack(err)
		}

		return nil, nil
	}
}

func (m *MakeAdminHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Make admin",
		Description:  "Give a user admin privileges",
		Tag:          "Auth",
		Code:         http.StatusAccepted,
		Method:       http.MethodPost,
		Path:         "/auth/admin",
		GenerateSpec: true,
	}
}

func (m *MakeAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
		middleware.Admin(middleware.AdminOpts{
			Users: m.users,
		}),
	}
}
