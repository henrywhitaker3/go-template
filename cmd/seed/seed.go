package seed

import (
	"strconv"

	"github.com/henrywhitaker3/go-template/database/seed"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/spf13/cobra"
)

func New(app *app.App) *cobra.Command {
	return &cobra.Command{
		Use:    "seed [kind] [count]",
		Short:  "Seed the database",
		Args:   cobra.ExactArgs(2),
		Hidden: app.Config.Environment != "dev",
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			seeder := seed.New(app)
			return seeder.Seed(cmd.Context(), args[0], count)
		},
	}
}
