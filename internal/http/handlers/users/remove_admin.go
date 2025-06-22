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

func (m *RemoveAdminHandler) Handler() common.Handler[AdminRequest, any] {
	return func(c echo.Context, req AdminRequest) (*any, error) {
		user, err := m.users.Get(c.Request().Context(), req.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: user not found", common.ErrValidation)
			}
			return nil, common.Stack(err)
		}

		if err := m.users.RemoveAdmin(c.Request().Context(), user); err != nil {
			return nil, common.Stack(err)
		}

		return nil, nil
	}
}

func (m *RemoveAdminHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Remove admin",
		Description:  "Remove admin privileges form a user",
		Tag:          "Auth",
		Code:         http.StatusAccepted,
		Method:       http.MethodDelete,
		Path:         "/auth/admin",
		GenerateSpec: true,
	}
}

func (m *RemoveAdminHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Authenticated(),
		middleware.Admin(middleware.AdminOpts{
			Users: m.users,
		}),
	}
}
