package migrate

import (
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/windowframe/database/postgres"
	"github.com/spf13/cobra"
)

func down(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: "Run the down migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return boiler.MustResolve[*postgres.Migrator](b).Up()
		},
	}
}
