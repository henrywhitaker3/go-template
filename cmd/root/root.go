package root

import (
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/cmd/consume"
	"github.com/henrywhitaker3/go-template/cmd/migrate"
	"github.com/henrywhitaker3/go-template/cmd/routes"
	"github.com/henrywhitaker3/go-template/cmd/secrets"
	"github.com/henrywhitaker3/go-template/cmd/seed"
	"github.com/henrywhitaker3/go-template/cmd/serve"
	"github.com/henrywhitaker3/go-template/cmd/token"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api",
		Short:   "Golang template API",
		Version: string(b.Version()),
		GroupID: "app",
	}

	cmd.AddGroup(&cobra.Group{
		ID:    "app",
		Title: "Application commands",
	})
	cmd.AddGroup(&cobra.Group{
		ID:    "unconf",
		Title: "Configuration commands",
	})

	cmd.AddCommand(serve.New(b))
	cmd.AddCommand(migrate.New(b))
	cmd.AddCommand(routes.New(b))
	cmd.AddCommand(consume.New(b))
	cmd.AddCommand(seed.New(b))
	cmd.AddCommand(secrets.New())
	cmd.AddCommand(token.New(b))

	cmd.PersistentFlags().
		StringP("config", "c", "go-template.yaml", "The path to the api config file")

	return cmd
}
