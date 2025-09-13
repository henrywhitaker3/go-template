package routes

import (
	"fmt"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/windowframe/http"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:     "routes",
		Short:   "Display all the routes registered for the api",
		GroupID: "app",
		PreRun: func(cmd *cobra.Command, args []string) {
			app.RegisterServe(b)
			b.MustBootstrap()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			server, err := boiler.Resolve[*http.HTTP](b)
			if err != nil {
				return err
			}
			routes := server.Routes()
			for _, route := range routes {
				fmt.Printf("%s    %s\n", route.Method, route.Path)
			}
			return nil
		},
	}
}
