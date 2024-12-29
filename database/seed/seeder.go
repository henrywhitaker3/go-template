package seed

import (
	"context"
	"database/sql"
	"errors"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/logger"
)

var (
	ErrSeederNotFound = errors.New("seeder not found")
)

type SeedFunc func(context.Context, *app.App) error

type Seeder struct {
	app *app.App
}

func New(app *app.App) *Seeder {
	return &Seeder{
		app: app,
	}
}

func (s *Seeder) Seed(ctx context.Context, name string, count int) error {
	logger := logger.Logger(ctx).With("seeder", name, "count", count)
	f, ok := seeders[name]
	if !ok {
		logger.Error("seeder not found")
		return ErrSeederNotFound
	}
	orig := *s.app.Queries

	dbtx, err := s.app.Database.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer dbtx.Rollback()

	*s.app.Queries = *orig.WithTx(dbtx)

	logger.Info("seeding")
	for i := range count {
		logger.Debugf("running iteration %d", i+1)
		if err := f(ctx, s.app); err != nil {
			return err
		}
	}

	*s.app.Queries = orig

	if err := dbtx.Commit(); err != nil {
		return err
	}

	return nil
}
