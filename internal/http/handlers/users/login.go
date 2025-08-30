package users

import (
	"net/http"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http/common"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/windowframe/tracing"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/labstack/echo/v4"
)

type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
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

func (l *LoginHandler) Handler() common.Handler[LoginRequest, any] {
	return func(c echo.Context, req LoginRequest) (*any, error) {
		ctx, span := tracing.NewSpan(c.Request().Context(), "Login")
		defer span.End()

		user, err := l.users.Login(ctx, req.Email, req.Password)
		if err != nil {
			metrics.Logins.WithLabelValues("false").Inc()
			return nil, common.ErrUnauth
		}

		token, err := l.jwt.NewForUser(user, time.Minute*5)
		if err != nil {
			return nil, common.Stack(err)
		}

		refresh, err := l.users.CreateRefreshToken(ctx, user.ID, time.Hour*24*30)
		if err != nil {
			return nil, common.Stack(err)
		}

		metrics.Logins.WithLabelValues("true").Inc()

		common.SetUserAuthCookie(c, l.domain, token)
		common.SetUserRefreshTokenCookie(c, l.domain, refresh)

		return nil, nil
	}
}

func (m *LoginHandler) Metadata() common.Metadata {
	return common.Metadata{
		Name:         "Login",
		Description:  "Login as a user",
		Tag:          "Auth",
		Code:         http.StatusOK,
		Method:       http.MethodPost,
		Path:         "/auth/login",
		GenerateSpec: true,
	}
}

func (l *LoginHandler) Middleware() []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{}
}
