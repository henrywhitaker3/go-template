package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	WorkerExecutions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "worker_executions_count",
		Help: "The number of worker executions completed",
	}, []string{"name"})
	WorkerExecutionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "worker_execution_errors_count",
		Help: "The number of worker execution errors",
	}, []string{"name"})

	Logins = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "logins_count",
		Help: "The number of logins",
	}, []string{"success"})
	Registrations = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "registrations_count",
		Help: "The number of registrations",
	})

	QueueTasksPushed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "queue_tasks_pushed_total",
		Help: "The number of tasks pushed to queue",
	}, []string{"queue", "task"})
	QueueTasksPushFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "queue_tasks_pushed_failures_total",
		Help: "The number of errors pushing a task to the queue",
	}, []string{"queue", "task"})

	QueueTasksProcessed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "queue_tasks_processed_total",
		Help: "The number of tasks processed by the consumer",
	}, []string{"task"})
	QueueTasksProcessedErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "queue_tasks_processed_errors_total",
		Help: "The number of errors encountered by the consumer",
	}, []string{"task"})
	QueueTasksProcessedDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "queue_tasks_processed_duration_seconds",
		Help: "The length of time taken for a task to be processed in seconds",
	}, []string{"task"})

	ApiMetrics = []prometheus.Collector{
		WorkerExecutions,
		WorkerExecutionErrors,
		Logins,
		Registrations,
		QueueTasksPushed,
		QueueTasksPushFailures,
	}

	QueueConsumerMetrics = []prometheus.Collector{
		QueueTasksProcessedDuration,
		QueueTasksProcessed,
		QueueTasksProcessedErrors,
	}
)

type Metrics struct {
	e *echo.Echo

	port int

	Registry prometheus.Registerer
	Gatherer prometheus.Gatherer
	reg      *sync.Once
}

func New(port int) *Metrics {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	reg := prometheus.NewRegistry()

	m := &Metrics{
		e:        e,
		port:     port,
		Registry: reg,
		Gatherer: reg,
		reg:      &sync.Once{},
	}

	m.reg.Do(func() {
		m.Registry.MustRegister(collectors.NewBuildInfoCollector())
		m.Registry.MustRegister(collectors.NewGoCollector())
		m.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	})

	m.e.GET("/metrics", echoprometheus.NewHandlerWithConfig(echoprometheus.HandlerConfig{
		Gatherer: m.Gatherer,
	}))

	return m
}

func (m *Metrics) Start(ctx context.Context) error {
	slog.Info("starting metrics server", "port", m.port)
	if err := m.e.Start(fmt.Sprintf(":%d", m.port)); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	return nil
}

func (m *Metrics) Stop(ctx context.Context) error {
	slog.Info("stopping metrics server")
	return m.e.Shutdown(ctx)
}

func (m *Metrics) Register(metrics []prometheus.Collector) {
	for _, metric := range metrics {
		m.Registry.Register(metric)
	}
}
