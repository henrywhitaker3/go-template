package workers_test

import (
	"context"
	"testing"
	"time"

	"github.com/henrywhitaker3/go-template/internal/test"
	"github.com/stretchr/testify/require"
)

type testWorker struct {
	interval   time.Duration
	timeout    time.Duration
	executions int
}

func (t *testWorker) Name() string {
	return "tester"
}

func (t *testWorker) Interval() time.Duration {
	return t.interval
}

func (t *testWorker) Timeout() time.Duration {
	return t.timeout
}

func (t *testWorker) Run(ctx context.Context) error {
	t.executions++
	return nil
}

func (t *testWorker) Executions() int {
	return t.executions
}

func TestItRunsWorkers(t *testing.T) {
	app, cancel := test.App(t)
	defer cancel()

	worker := &testWorker{
		interval:   time.Millisecond,
		timeout:    time.Millisecond * 5,
		executions: 0,
	}

	app.Runner.Register(worker)

	time.Sleep(time.Millisecond * 2)

	require.Equal(t, 1, worker.Executions())
}