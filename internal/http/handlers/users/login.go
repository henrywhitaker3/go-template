package users

import (
	"fmt"
	"net/http"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/http/middleware"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (l LoginRequest) Validate() error {
	if l.Email == "" {
		return fmt.Errorf("%w email", common.ErrRequiredField)
	}
	if l.Password == "" {
		return fmt.Errorf("%w password", common.ErrRequiredField)
	}
	return nil
}

type LoginHandler struct {
	users  *users.Users
	jwt    *jwt.Jwt
	domain string
}

func NewLogin(b *boiler.Boiler) *LoginHandler {
	return &LoginHandler{
		users:  boiler.MustResolve[*users.Users](b),
		jwt:    boiler.MustResolve[*jwt.Jwt](b),
		domain: boiler.MustResolve[*config.Config](b).Url,
	}
}

func (l *LoginHandler) Handler() echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx, span := tracing.NewSpan(c.Request().Context(), "Login")
		defer span.End()

		req, ok := common.GetRequest[LoginRequest](ctx)
		if !ok {
			return common.ErrBadRequest
		}

		user, err := l.users.Login(ctx, req.Email, req.Password)
		if err != nil {
			metrics.Logins.WithLabelValues("false").Inc()
			return common.ErrUnauth
		}

		token, err := l.jwt.NewForUser(user, time.Minute*5)
		if err != nil {
			return common.Stack(err)
		}

		refresh, err := l.users.CreateRefreshToken(ctx, user.ID, time.Hour*24*30)
		if err != nil {
			return common.Stack(err)
		}

		metrics.Logins.WithLabelValues("true").Inc()

		common.SetUserAuthCookie(c, l.domain, token)
		common.SetUserRefreshTokenCookie(c, l.domain, refresh)

		return c.NoContent(http.StatusOK)
	}
}

func (l *LoginHandler) Method() string {
	return http.MethodPost
}

func (l *LoginHandler) Path() string {
	return "/auth/login"
}

func (l *LoginHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		middleware.Bind[LoginRequest](),
	}
}
