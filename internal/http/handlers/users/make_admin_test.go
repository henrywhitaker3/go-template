package users_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/test"
	iusers "github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/windowframe/uuid"
	"github.com/stretchr/testify/require"
)

func TestItMakesUsersAdmin(t *testing.T) {
	b := test.Boiler(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	us, err := boiler.Resolve[*iusers.Users](b)
	require.Nil(t, err)

	admin, _ := test.User(t, b)
	require.Nil(t, us.MakeAdmin(ctx, admin))
	adminToken := test.Token(t, b, admin)

	user, _ := test.User(t, b)

	badUser, _ := test.User(t, b)
	badUserToken := test.Token(t, b, badUser)

	type testCase struct {
		name   string
		token  string
		target uuid.UUID
		code   int
	}

	tcs := []testCase{
		{
			name:   "404s when id is not a user",
			token:  adminToken,
			target: uuid.MustNew(),
			code:   http.StatusUnprocessableEntity,
		},
		{
			name:   "403s when a normal user tries to make admin",
			token:  badUserToken,
			target: badUser.ID,
			code:   http.StatusForbidden,
		},
		{
			name:   "admin can make another user an admin",
			token:  adminToken,
			target: user.ID,
			code:   http.StatusAccepted,
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			rec := test.Post(t, b, "/auth/admin", users.AdminRequest{
				ID: c.target,
			}, c.token)
			require.Equal(t, c.code, rec.Code)
			if rec.Code == http.StatusAccepted {
				new, err := us.Get(ctx, c.target)
				require.Nil(t, err)
				require.True(t, new.Admin)
			}
		})
	}
}
