package consume

import (
	"context"
	"fmt"

	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/spf13/cobra"
)

func New(app *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "consume [queue]",
		Short: "Run a queue consumer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			app.Metrics.Register(metrics.QueueConsumerMetrics)

			consumer, err := app.Worker(cmd.Context(), []queue.Queue{queue.Queue(args[0])})
			if err != nil {
				return fmt.Errorf("failed to instantiate queue consumer: %w", err)
			}
			defer consumer.Shutdown(context.Background())

			go app.Probes.Start(cmd.Context())

			go func() {
				<-cmd.Context().Done()
				ctx := context.Background()
				probes.Unready()

				app.Metrics.Stop(ctx)
				app.Probes.Stop(ctx)
			}()

			go app.Metrics.Start(cmd.Context())

			probes.Ready()
			probes.Healthy()

			consumer.RegisterMetrics(app.Metrics.Registry)

			return consumer.Consume()
		},
	}
}
