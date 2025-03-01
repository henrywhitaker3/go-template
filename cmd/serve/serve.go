package serve

import (
	"context"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/http"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/henrywhitaker3/go-template/internal/workers"
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

			probes, err := boiler.Resolve[*probes.Probes](b)
			if err != nil {
				return err
			}
			go probes.Start(cmd.Context())
			defer probes.Stop(context.Background())

			runner, err := boiler.Resolve[*workers.Runner](b)
			if err != nil {
				return err
			}
			go runner.Run()

			probes.Ready()
			probes.Healthy()

			http, err := boiler.Resolve[*http.Http](b)
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
