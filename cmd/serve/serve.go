package serve

import (
	"context"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/spf13/cobra"
)

func New(app *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the api server",
		RunE: func(cmd *cobra.Command, args []string) error {
			app.Metrics.Register(metrics.ApiMetrics)

			go app.Probes.Start(cmd.Context())

			go func() {
				<-cmd.Context().Done()
				ctx := context.Background()
				probes.Unready()

				app.Metrics.Stop(ctx)
				app.Probes.Stop(ctx)
				app.Http.Stop(ctx)
				app.Runner.Stop()
			}()

			go app.Metrics.Start(cmd.Context())

			app.Runner.Run()

			probes.Ready()
			probes.Healthy()

			return app.Http.Start(cmd.Context())
		},
	}
}
