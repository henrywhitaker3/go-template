package users_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/uuid"
	"github.com/stretchr/testify/require"
)

func TestItRemovesUsersAdmin(t *testing.T) {
	app, cancel := test.App(t)
	defer cancel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	admin, _ := test.User(t, app)
	require.Nil(t, app.Users.MakeAdmin(ctx, admin))
	adminToken := test.Token(t, app, admin)

	user, _ := test.User(t, app)

	badUser, _ := test.User(t, app)
	badUserToken := test.Token(t, app, badUser)

	type testCase struct {
		name   string
		token  string
		target uuid.UUID
		code   int
	}

	tcs := []testCase{
		{
			name:   "422s when id is not a user",
			token:  adminToken,
			target: uuid.MustNew(),
			code:   http.StatusUnprocessableEntity,
		},
		{
			name:   "403s when a normal user tries to remove admin",
			token:  badUserToken,
			target: badUser.ID,
			code:   http.StatusForbidden,
		},
		{
			name:   "admin can remove another user an admin",
			token:  adminToken,
			target: user.ID,
			code:   http.StatusAccepted,
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			rec := test.Delete(t, app, "/auth/admin", users.AdminRequest{
				ID: c.target,
			}, c.token)
			require.Equal(t, c.code, rec.Code)
			if rec.Code == http.StatusAccepted {
				new, err := app.Users.Get(ctx, c.target)
				require.Nil(t, err)
				require.False(t, new.Admin)
			}
		})
	}
}
