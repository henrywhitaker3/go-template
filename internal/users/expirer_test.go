package users_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/stretchr/testify/require"
)

func TestItDeletesExpiredTokens(t *testing.T) {
	b := test.Boiler(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	svc := boiler.MustResolve[*users.Users](b)

	user, _ := test.User(t, b)
	refresh, err := svc.CreateRefreshToken(ctx, user.ID, time.Second)
	require.Nil(t, err)

	run := users.NewExpirer(boiler.MustResolve[*queries.Queries](b))

	time.Sleep(time.Second * 2)

	require.Nil(t, run.Run(ctx))

	_, err = svc.GetUserByRefreshToken(ctx, refresh)
	require.NotNil(t, err)
	require.ErrorIs(t, err, sql.ErrNoRows)
}
