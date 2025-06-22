package users

import (
	"net/http"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/validation"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type RegisterRequest struct {
	Name                 string `json:"name"                  validate:"required,max=255"`
	Email                string `json:"email"                 validate:"required,email"`
	Password             string `json:"password"              validate:"required"`
	PasswordConfirmation string `json:"password_confirmation" validate:"required"`
}

type RegisterResponse struct {
	User  *users.User `json:"user"`
	Token string      `json:"token"`
}

type RegisterHandler struct {
	users *users.Users
	jwt   *jwt.Jwt
}

func NewRegister(b *boiler.Boiler) *RegisterHandler {
	return &RegisterHandler{
		users: boiler.MustResolve[*users.Users](b),
		jwt:   boiler.MustResolve[*jwt.Jwt](b),
	}
}

func (r *RegisterHandler) Handler() common.Handler[RegisterRequest, RegisterResponse] {
	return func(c echo.Context, req RegisterRequest) (*RegisterResponse, error) {
		if req.Password != req.PasswordConfirmation {
			return nil, validation.Build().
				With("password_confirmation", "password and password_confirmation must match")
		}
		user, err := r.users.CreateUser(c.Request().Context(), users.CreateParams{
			Name:     req.Name,
			Email:    req.Email,
			Password: req.Password,
		})
		if err != nil {
			return nil, common.Stack(err)
		}

		token, err := r.jwt.NewForUser(user, time.Hour)
		if err != nil {
			return nil, common.Stack(err)
		}

		metrics.Registrations.Inc()

		return &RegisterResponse{
			User:  user,
			Token: token,
		}, nil
	}
}

func (m *RegisterHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Register new user",
		Description:  "Register a new user account",
		Tag:          "Auth",
		Code:         http.StatusCreated,
		Method:       http.MethodPost,
		Path:         "/auth/register",
		GenerateSpec: true,
	}
}

func (r *RegisterHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{}
}
