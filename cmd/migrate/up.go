package migrate

import (
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/postgres"
	"github.com/spf13/cobra"
)

func up(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Run the up migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return boiler.MustResolve[*postgres.Migrator](b).Up()
		},
	}
}
