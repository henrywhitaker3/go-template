package migrate

import (
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/postgres"
	"github.com/spf13/cobra"
)

func fresh(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:   "fresh",
		Short: "Drop the db and run the up migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return boiler.MustResolve[*postgres.Migrator](b).Fresh()
		},
	}
}
