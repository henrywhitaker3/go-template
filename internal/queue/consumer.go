package queue

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/hibiken/asynq"
	ametrics "github.com/hibiken/asynq/x/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Queue string
type Task string

const (
	DefaultQueue Queue = "default"
)

type ShutdownFunc = func(context.Context) error

type Worker struct {
	server    *asynq.Server
	inspector *asynq.Inspector
	handlers  map[Task]Handler
	shutdown  []ShutdownFunc
}

type ServerOpts struct {
	Queues []Queue
	Redis  RedisOpts
}

type RedisOpts struct {
	Addr        string
	Password    string
	DB          int
	OtelEnabled bool
}

func (r RedisOpts) Client() redis.UniversalClient {
	client := redis.NewClient(&redis.Options{
		Addr:     r.Addr,
		Password: r.Password,
		DB:       r.DB,
	})

	if r.OtelEnabled {
		redisotel.InstrumentTracing(client, redisotel.WithDBStatement(true))
	}

	return client
}

func NewWorker(ctx context.Context, opts ServerOpts) (*Worker, error) {
	queues := map[string]int{}
	for _, queue := range opts.Queues {
		logger.Logger(ctx).Debug("consuming from queue", "queue", queue)
		queues[string(queue)] = 9
	}
	srv := asynq.NewServerFromRedisClient(
		opts.Redis.Client(),
		asynq.Config{
			Concurrency: runtime.NumCPU(),
			BaseContext: func() context.Context { return ctx },
			Logger: &asynqLogger{
				log: slog.Default(),
			},
			Queues: queues,
		},
	)
	if err := srv.Ping(); err != nil {
		return nil, err
	}

	inspector := asynq.NewInspector(asynq.RedisClientOpt{
		Addr:     opts.Redis.Addr,
		Password: opts.Redis.Password,
		DB:       opts.Redis.DB,
	})

	return &Worker{
		server:    srv,
		inspector: inspector,
		handlers:  map[Task]Handler{},
		shutdown:  []func(ctx context.Context) error{},
	}, nil
}

type Handler interface {
	Handle(ctx context.Context, payload []byte) error
}

func (w *Worker) handler(ctx context.Context, task *asynq.Task) error {
	ctx, span := tracing.NewSpan(
		ctx,
		"HandleTask",
		trace.WithAttributes(attribute.String("task", task.Type())),
		trace.WithSpanKind(trace.SpanKindConsumer),
	)
	defer span.End()

	labels := prometheus.Labels{"task": task.Type()}

	start := time.Now()
	handler, ok := w.handlers[Task(task.Type())]
	if !ok {
		metrics.QueueTasksProcessedErrors.With(labels).Inc()
		return fmt.Errorf("no handler registered for task: %w", asynq.SkipRetry)
	}
	err := handler.Handle(ctx, task.Payload())
	end := time.Since(start)

	metrics.QueueTasksProcessed.With(labels).Inc()
	metrics.QueueTasksProcessedDuration.With(labels).Observe(end.Seconds())
	if err != nil {
		metrics.QueueTasksProcessedErrors.With(labels).Inc()
	}
	return err
}

func (w *Worker) RegisterHandler(kind Task, h Handler) {
	w.handlers[kind] = h
}

func (w *Worker) RegisterShutdown(f ShutdownFunc) {
	w.shutdown = append(w.shutdown, f)
}

func (w *Worker) Shutdown(ctx context.Context) error {
	for _, f := range w.shutdown {
		if err := f(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Run the queue worker. Blocking.
func (w *Worker) Consume() error {
	return w.server.Run(asynq.HandlerFunc(w.handler))
}

func (w *Worker) RegisterMetrics(reg prometheus.Registerer) {
	reg.Register(ametrics.NewQueueMetricsCollector(w.inspector))
}
