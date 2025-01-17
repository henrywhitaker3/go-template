package workers

import (
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
)

type Monitor struct {
	executions prometheus.Counter
	failures   prometheus.Counter
	skipped    prometheus.Counter
	duration   prometheus.Observer
}

type MonitorOpts struct {
	Executions prometheus.Counter
	Failures   prometheus.Counter
	Skipped    prometheus.Counter
	Duration   prometheus.Observer
}

func NewMonitor(opts MonitorOpts) *Monitor {
	return &Monitor{
		executions: opts.Executions,
		failures:   opts.Failures,
		skipped:    opts.Skipped,
		duration:   opts.Duration,
	}
}

func (m *Monitor) IncrementJob(id uuid.UUID, name string, tags []string, status gocron.JobStatus) {
	var metric prometheus.Counter
	switch status {
	case gocron.Fail:
		metric = m.failures
	case gocron.Skip:
		fallthrough
	case gocron.SingletonRescheduled:
		metric = m.skipped
	}
	if m.executions != nil {
		m.executions.Inc()
	}
	if metric != nil {
		metric.Inc()
	}
}

func (m *Monitor) RecordJobTiming(startTime, endTime time.Time, id uuid.UUID, name string, tags []string) {
	if m.duration != nil {
		dur := endTime.Sub(startTime)
		m.duration.Observe(dur.Seconds())
	}
}
