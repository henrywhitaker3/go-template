package seed

import (
	"strconv"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/database/seed"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	hidden := true
	conf, err := boiler.Resolve[*config.Config](b)
	if err == nil && conf.Environment == "dev" {
		hidden = false
	}
	return &cobra.Command{
		Use:     "seed [kind] [count]",
		Short:   "Seed the database",
		Args:    cobra.ExactArgs(2),
		Hidden:  hidden,
		GroupID: "app",
		PreRun: func(cmd *cobra.Command, args []string) {
			app.RegisterBase(b)
			b.MustBootstrap()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			count, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			seeder := seed.New(b)
			return seeder.Seed(cmd.Context(), args[0], count)
		},
	}
}
