package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/go-template/internal/uuid"
	"github.com/stretchr/testify/require"
)

func TestItCreatesAUserJwt(t *testing.T) {
	b := test.Boiler(t)

	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	user := &users.User{
		ID:        uuid.MustNew(),
		Name:      test.Word(),
		Email:     test.Email(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	token, err := jwt.NewForUser(user, time.Second)
	require.Nil(t, err)

	valid, err := jwt.VerifyUser(ctx, token)
	require.Nil(t, err)
	require.Equal(t, user.ID, valid.ID)
	require.Equal(t, user.Name, valid.Name)
	require.Equal(t, user.Email, valid.Email)

	// Test it fails validation after it has expired
	time.Sleep(time.Second * 2)

	_, err = jwt.VerifyUser(ctx, token)
	require.NotNil(t, err)
}

func TestItReturnsTheCorrectExpiryTime(t *testing.T) {
	b := test.Boiler(t)

	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	now := time.Now()
	token, err := jwt.Generic("bongo", time.Minute)
	require.Nil(t, err)

	expiry, err := jwt.Expiry(ctx, token)
	require.Nil(t, err)
	require.GreaterOrEqual(t, now.Add(time.Minute), expiry)
}
