package users_test

import (
	"net/http"
	"testing"

	"github.com/henrywhitaker3/go-template/internal/http/handlers/users"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/stretchr/testify/require"
)

func TestItRegistersUsers(t *testing.T) {
	b := test.Boiler(t)

	type testCase struct {
		name string
		req  users.RegisterRequest
		code int
	}

	email := test.Email()
	password := test.Sentence(5)

	tcs := []testCase{
		{
			name: "registers user with valid request",
			req: users.RegisterRequest{
				Name:                 test.Word(),
				Email:                email,
				Password:             password,
				PasswordConfirmation: password,
			},
			code: http.StatusCreated,
		},
		{
			name: "doesn't register user with duplicate email",
			req: users.RegisterRequest{
				Name:                 test.Word(),
				Email:                email,
				Password:             password,
				PasswordConfirmation: password,
			},
			code: http.StatusUnprocessableEntity,
		},
		{
			name: "422s with no name",
			req: users.RegisterRequest{
				Email:                test.Email(),
				Password:             password,
				PasswordConfirmation: password,
			},
			code: http.StatusUnprocessableEntity,
		},
		{
			name: "422s with no email",
			req: users.RegisterRequest{
				Name:                 test.Word(),
				Password:             password,
				PasswordConfirmation: password,
			},
			code: http.StatusUnprocessableEntity,
		},
		{
			name: "422s with no password",
			req: users.RegisterRequest{
				Name:                 test.Word(),
				Email:                test.Sentence(5),
				PasswordConfirmation: password,
			},
			code: http.StatusUnprocessableEntity,
		},
		{
			name: "422s with no password_confirmation",
			req: users.RegisterRequest{
				Name:     test.Word(),
				Email:    test.Sentence(5),
				Password: password,
			},
			code: http.StatusUnprocessableEntity,
		},
		{
			name: "422s with non-matching password_confirmation",
			req: users.RegisterRequest{
				Name:                 test.Word(),
				Email:                test.Sentence(5),
				Password:             password,
				PasswordConfirmation: test.Sentence(5),
			},
			code: http.StatusUnprocessableEntity,
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			rec := test.Post(t, b, "/auth/register", c.req, "")
			require.Equal(t, c.code, rec.Code)
			t.Log(rec.Body.String())
		})
	}
}
