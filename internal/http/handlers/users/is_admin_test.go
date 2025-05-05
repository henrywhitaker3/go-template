package users_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/stretchr/testify/require"
)

func TestItChecksIfUserIsAdmin(t *testing.T) {
	b := test.Boiler(t)

	admin, _ := test.User(t, b)
	require.Nil(t, boiler.MustResolve[*users.Users](b).MakeAdmin(context.Background(), admin))
	adminToken := test.Token(t, b, admin)

	notAdmin, _ := test.User(t, b)
	notAdminToken := test.Token(t, b, notAdmin)

	tcs := []struct {
		name  string
		token string
		code  int
	}{
		{
			name:  "returns 200 when user is an admin",
			token: adminToken,
			code:  http.StatusOK,
		},
		{
			name:  "returns 403 when not an admin",
			token: notAdminToken,
			code:  http.StatusForbidden,
		},
		{
			name:  "returns 401 when no token specified",
			token: "",
			code:  http.StatusUnauthorized,
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			rec := test.Get(t, b, "/auth/admin", c.token)
			require.Equal(t, c.code, rec.Code)
		})
	}
}
