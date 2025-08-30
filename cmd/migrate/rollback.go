package migrate

import (
	"fmt"
	"strconv"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/windowframe/database/postgres"
	"github.com/spf13/cobra"
)

func rollback(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback [steps:1]",
		Short: "Rollback a migration",
		RunE: func(cmd *cobra.Command, args []string) error {
			steps := 1
			if len(args) > 0 {
				i, err := strconv.Atoi(args[0])
				if err != nil {
					return fmt.Errorf("parse steps: %w", err)
				}
				steps = i
			}
			return boiler.MustResolve[*postgres.Migrator](b).Rollback(steps)
		},
	}
}
