package workers

import (
	"context"
	"fmt"

	"github.com/go-co-op/gocron/v2"
	"github.com/henrywhitaker3/rueidisleader"
	"github.com/redis/rueidis"
	"go.uber.org/zap"
)

type LockerOpts struct {
	Redis  rueidis.Client
	Logger *zap.SugaredLogger
	Topic  string
}

type Locker struct {
	leader *rueidisleader.Leader
	logger *zap.SugaredLogger
}

func NewLocker(opts LockerOpts) (*Locker, error) {
	leader, err := rueidisleader.New(&rueidisleader.LeaderOpts{
		Client: opts.Redis,
		Topic:  opts.Topic,
		Logger: rueidisleader.ZapLogger(opts.Logger),
	})
	if err != nil {
		return nil, fmt.Errorf("instantiate leader election: %w", err)
	}

	return &Locker{
		leader: leader,
		logger: opts.Logger,
	}, nil
}

func (l *Locker) Run(ctx context.Context) {
	l.leader.Run(ctx)
}

func (l *Locker) Initialised() <-chan struct{} {
	return l.leader.Initialised()
}

type fakeLock struct {
	call func()
}

func (f fakeLock) Unlock(context.Context) error {
	if f.call != nil {
		f.call()
	}
	return nil
}

func (l *Locker) Lock(ctx context.Context, key string) (gocron.Lock, error) {
	log := l.logger.With("key", key)
	log.Debug("acquiring lock")
	if l.leader.IsLeader() {
		return fakeLock{
			call: func() {
				log.Debug("releasing lock")
			},
		}, nil
	}
	log.Debug("failed to acquire lock")
	return fakeLock{}, fmt.Errorf("not the leader")
}

var _ gocron.Locker = &Locker{}
var _ gocron.Lock = fakeLock{}
