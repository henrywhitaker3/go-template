package workers

import (
	"context"
	"fmt"

	"github.com/go-co-op/gocron/v2"
	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidislock"
)

var (
	_ gocron.Lock   = &RueidisLock{}
	_ gocron.Locker = &RueidisLocker{}
)

type RueidisLock struct {
	key    string
	cancel context.CancelFunc
}

func (r *RueidisLock) Unlock(ctx context.Context) error {
	logger.Logger(ctx).Debugw("releasing lock", "key", r.key)
	r.cancel()
	return nil
}

type RueidisLocker struct {
	r      rueidis.Client
	prefix string
	lock   rueidislock.Locker
}

type LockerOpts struct {
	Redis rueidis.Client
	// Optional key prefix for lock keys
	Prefix string
}

func NewLocker(opts LockerOpts) (*RueidisLocker, error) {
	lock, err := rueidislock.NewLocker(rueidislock.LockerOption{
		ClientBuilder: func(option rueidis.ClientOption) (rueidis.Client, error) {
			return opts.Redis, nil
		},
		KeyMajority: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate rueidis locker: %w", err)
	}
	return &RueidisLocker{
		r:      opts.Redis,
		prefix: opts.Prefix,
		lock:   lock,
	}, nil
}

func (r *RueidisLocker) Lock(ctx context.Context, key string) (gocron.Lock, error) {
	if r.prefix != "" {
		key = fmt.Sprintf("%s:%s", r.prefix, key)
	}
	logger := logger.Logger(ctx).With("key", key)
	logger.Debug("acquiring lock")
	_, unlock, err := r.lock.TryWithContext(ctx, key)
	if err != nil {
		logger.Debugw("failed to acquire lock", "error", err)
		return nil, err
	}
	return &RueidisLock{key: key, cancel: unlock}, nil
}
