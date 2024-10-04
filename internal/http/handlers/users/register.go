package users

import (
	"fmt"
	"net/http"
	"time"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type RegisterRequest struct {
	Name                 string `json:"name"`
	Email                string `json:"email"`
	Password             string `json:"password"`
	PasswordConfirmation string `json:"password_confirmation"`
}

func (r RegisterRequest) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("%w name", common.ErrRequiredField)
	}
	if r.Email == "" {
		return fmt.Errorf("%w email", common.ErrRequiredField)
	}
	if r.Password == "" {
		return fmt.Errorf("%w password", common.ErrRequiredField)
	}
	if r.PasswordConfirmation == "" {
		return fmt.Errorf("%w password_confirmation", common.ErrRequiredField)
	}
	if r.Password != r.PasswordConfirmation {
		return fmt.Errorf("%w password and password_confirmation", common.ErrNotEqual)
	}
	return nil
}

type RegisterResponse struct {
	User  *users.User `json:"user"`
	Token string      `json:"token"`
}

type RegisterHandler struct {
	app *app.App
}

func NewRegister(app *app.App) *RegisterHandler {
	return &RegisterHandler{app: app}
}

func (r *RegisterHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		req, ok := common.GetRequest[RegisterRequest](c.Request().Context())
		if !ok {
			return common.ErrBadRequest
		}

		user, err := r.app.Users.CreateUser(c.Request().Context(), users.CreateParams{
			Name:     req.Name,
			Email:    req.Email,
			Password: req.Password,
		})
		if err != nil {
			return common.Stack(err)
		}

		token, err := r.app.Jwt.NewForUser(user, time.Hour)
		if err != nil {
			return common.Stack(err)
		}

		metrics.Registrations.Inc()

		return c.JSON(http.StatusCreated, RegisterResponse{
			User:  user,
			Token: token,
		})
	}
}

func (r *RegisterHandler) Method() string {
	return http.MethodPost
}

func (r *RegisterHandler) Path() string {
	return "/auth/register"
}

func (r *RegisterHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Bind[RegisterRequest](),
	}
}
