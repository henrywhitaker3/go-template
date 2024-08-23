package routes

import (
	"fmt"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/spf13/cobra"
)

func New(app *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "routes",
		Short: "Display all the routes registered for the api",
		Run: func(cmd *cobra.Command, args []string) {
			routes := app.Http.Routes()
			for _, route := range routes {
				fmt.Printf("%s    %s\n", route.Method, route.Path)
			}
		},
	}
}
