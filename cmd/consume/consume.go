package consume

import (
	"context"
	"fmt"

	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/spf13/cobra"
)

func New(b *boiler.Boiler) *cobra.Command {
	return &cobra.Command{
		Use:     "consume [queue]",
		Short:   "Run a queue consumer",
		GroupID: "app",
		PreRun: func(*cobra.Command, []string) {
			app.RegisterConsumers(b)
			b.MustBootstrap()
		},
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			metricsServer, err := boiler.Resolve[*metrics.Metrics](b)
			if err != nil {
				return err
			}
			metricsServer.Register(metrics.QueueConsumerMetrics)
			go metricsServer.Start(cmd.Context())
			defer metricsServer.Stop(context.Background())

			consumer, err := boiler.ResolveNamed[*queue.Worker](b, fmt.Sprintf("queue:%s", args[0]))
			if err != nil {
				return err
			}

			go func() {
				<-cmd.Context().Done()
				consumer.Shutdown(context.Background())
			}()

			consumer.RegisterMetrics(metricsServer.Registry)

			return consumer.Consume()
		},
	}
}
