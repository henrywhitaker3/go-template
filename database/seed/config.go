package seed

import (
	"context"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/henrywhitaker3/go-template/internal/users"
)

var (
	seeders = map[string]SeedFunc{
		"user": User,
	}
)

func User(ctx context.Context, app *app.App) error {
	_, err := app.Users.CreateUser(ctx, users.CreateParams{
		Name:     test.Name(),
		Email:    test.Email(),
		Password: test.Letters(15),
	})
	return err
}
