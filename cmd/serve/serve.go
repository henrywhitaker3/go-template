package serve

import (
	"context"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/windowframe/http"
	"github.com/henrywhitaker3/windowframe/workers"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:     "serve",
		Short:   "Run the api server",
		GroupID: "app",
		PreRun: func(*cobra.Command, []string) {
			app.RegisterServe(b)
			b.MustBootstrap()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			metricsServer, err := boiler.Resolve[*metrics.Metrics](b)
			if err != nil {
				return err
			}
			metricsServer.Register(metrics.ApiMetrics)
			go metricsServer.Start(cmd.Context())
			defer metricsServer.Stop(context.Background())

			runner, err := boiler.Resolve[*workers.Runner](b)
			if err != nil {
				return err
			}
			go runner.Run()

			http, err := boiler.Resolve[*http.HTTP](b)
			if err != nil {
				return err
			}
			go func() {
				<-cmd.Context().Done()
				http.Stop(context.Background())
			}()

			return http.Start(cmd.Context())
		},
	}
}
