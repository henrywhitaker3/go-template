package workers

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/go-co-op/gocron/v2"
	"github.com/henrywhitaker3/rueidisleader"
	"github.com/redis/rueidis"
)

type LockerOpts struct {
	Redis  rueidis.Client
	Logger *slog.Logger
	Topic  string
}

type Locker struct {
	leader *rueidisleader.Leader

	locks map[string]bool
	mu    *sync.Mutex

	logger *slog.Logger
}

func NewLocker(opts LockerOpts) (*Locker, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	leader, err := rueidisleader.New(&rueidisleader.LeaderOpts{
		Client: opts.Redis,
		Topic:  opts.Topic,
		Logger: opts.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("instantiate leader election: %w", err)
	}

	return &Locker{
		leader: leader,
		locks:  map[string]bool{},
		mu:     &sync.Mutex{},
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
		l.mu.Lock()
		defer l.mu.Unlock()
		if _, ok := l.locks[key]; ok {
			return fakeLock{}, fmt.Errorf("already locked")
		}
		l.locks[key] = true
		return fakeLock{
			call: func() {
				log.Debug("releasing lock")
				l.mu.Lock()
				defer l.mu.Unlock()
				delete(l.locks, key)
			},
		}, nil
	}
	log.Debug("failed to acquire lock")
	return fakeLock{}, fmt.Errorf("not the leader")
}

var _ gocron.Locker = &Locker{}
var _ gocron.Lock = fakeLock{}
