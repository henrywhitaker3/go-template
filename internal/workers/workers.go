package workers

import (
	"context"
	"fmt"
	"time"

	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidislock"
)

type Worker interface {
	Name() string
	Run(ctx context.Context) error
	Interval() time.Duration
	Timeout() time.Duration
}

type Runner struct {
	locker rueidislock.Locker
	ctx    context.Context
}

func NewRunner(ctx context.Context, redis rueidis.Client) (*Runner, error) {
	locker, err := rueidislock.NewLocker(rueidislock.LockerOption{
		ClientBuilder: func(option rueidis.ClientOption) (rueidis.Client, error) {
			return redis, nil
		},
		KeyMajority: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialise locker: %w", err)
	}

	return &Runner{
		locker: locker,
		ctx:    ctx,
	}, nil
}

func (r *Runner) Register(w Worker) {
	tick := time.NewTicker(w.Interval())
	logger := logger.Logger(r.ctx)

	logger.Infow("registering worker", "name", w.Name(), "interval", w.Interval().String(), "timeout", w.Timeout().String())

	go func() {
		defer tick.Stop()
		for {
			select {
			case <-r.ctx.Done():
				logger.Infow("stopping worker", "name", w.Name())
				return
			case <-tick.C:
				ctx, cancel := context.WithTimeout(r.ctx, w.Timeout())

				_, release, err := r.locker.TryWithContext(ctx, w.Name())
				if err != nil {
					logger.Debugw("skipping executing worker", "name", w.Name(), "error", err)
					cancel()
					continue
				}

				metrics.WorkerExecutions.WithLabelValues(w.Name()).Inc()
				logger.Debugw("executing worker", "name", w.Name())

				if err := w.Run(ctx); err != nil {
					logger.Errorw("worker run failed", "name", w.Name(), "error", err)
					metrics.WorkerExecutionErrors.WithLabelValues(w.Name()).Inc()
				}

				// Release the lock, use the parent context so we still remove the
				// lock even if the child context has timed out
				release()
				cancel()
			}
		}
	}()
}
