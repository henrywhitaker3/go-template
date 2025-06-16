package users_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/stretchr/testify/require"
)

func TestItLogsOutAUser(t *testing.T) {
	b := test.Boiler(t)

	user, _ := test.User(t, b)

	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	token, err := jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)

	rec := test.Post(t, b, "/auth/logout", nil, token)

	require.Equal(t, http.StatusAccepted, rec.Code)
}
