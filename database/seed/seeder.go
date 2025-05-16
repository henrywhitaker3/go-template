package seed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/henrywhitaker3/boiler"
)

var (
	ErrSeederNotFound = errors.New("seeder not found")
)

type SeedFunc func(context.Context, *boiler.Boiler) error

type Seeder struct {
	b *boiler.Boiler
}

func New(b *boiler.Boiler) *Seeder {
	return &Seeder{
		b: b,
	}
}

func (s *Seeder) Seed(ctx context.Context, name string, count int) error {
	logger := slog.With("seeder", name, "count", count)
	f, ok := seeders[name]
	if !ok {
		logger.Error("seeder not found")
		return ErrSeederNotFound
	}

	logger.Info("seeding")
	for i := range count {
		logger.Debug(fmt.Sprintf("running iteration %d", i+1))
		if err := f(ctx, s.b); err != nil {
			return err
		}
	}

	return nil
}
