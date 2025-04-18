package migrate

import (
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "migrate",
		Short:   "Run database migrations",
		GroupID: "app",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			app.RegisterBase(b)
			b.MustBootstrap()
		},
	}

	cmd.AddCommand(up(b))
	cmd.AddCommand(down(b))

	return cmd
}
