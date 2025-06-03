package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/tracing"
	"github.com/hibiken/asynq"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Publisher struct {
	client *asynq.Client
}

type PublisherOpts struct {
	Redis RedisOpts
}

func NewPublisher(opts PublisherOpts) (*Publisher, error) {
	client := asynq.NewClientFromRedisClient(opts.Redis.Client())
	if err := client.Ping(); err != nil {
		return nil, err
	}

	return &Publisher{client: client}, nil
}

// Push a task in the queue
func (p *Publisher) Push(ctx context.Context, kind Task, payload any, opts ...asynq.Option) error {
	ctx, span := tracing.NewSpan(
		ctx,
		"PushToQueue",
		trace.WithAttributes(attribute.String("task", string(kind))),
		trace.WithSpanKind(trace.SpanKindProducer),
	)
	defer span.End()
	by, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal task payload: %w", err)
	}
	task := asynq.NewTask(string(kind), by, opts...)

	queue := mapTaskToQueue(kind)

	span.SetAttributes(attribute.String("queue", string(queue)))
	labels := prometheus.Labels{"queue": string(queue), "task": string(kind)}
	if _, err = p.client.EnqueueContext(ctx, task, asynq.Queue(string(queue))); err != nil {
		metrics.QueueTasksPushFailures.With(labels).Inc()
	}
	metrics.QueueTasksPushed.With(labels).Inc()

	return err
}
