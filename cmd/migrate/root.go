package migrate

import (
	"database/sql"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/postgres"
	"github.com/spf13/cobra"
)

var (
	m *postgres.Migrator
)

func New(b *boiler.Boiler) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "migrate",
		Short:   "Run database migrations",
		GroupID: "app",
		PreRun: func(cmd *cobra.Command, args []string) {
			app.RegisterBase(b)
			b.MustBootstrap()
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			db, err := boiler.Resolve[*sql.DB](b)
			if err != nil {
				return err
			}
			mig, err := postgres.NewMigrator(db)
			if err != nil {
				return err
			}
			m = mig
			return nil
		},
	}

	cmd.AddCommand(up())
	cmd.AddCommand(down())

	return cmd
}
