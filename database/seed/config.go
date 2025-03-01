package seed

import (
	"context"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
)

var (
	seeders = map[string]SeedFunc{
		"user": User,
	}
)

func User(ctx context.Context, b *boiler.Boiler) error {
	_, err := boiler.MustResolve[*users.Users](b).CreateUser(ctx, users.CreateParams{
		Name:     test.Name(),
		Email:    test.Email(),
		Password: test.Letters(15),
	})
	return err
}
