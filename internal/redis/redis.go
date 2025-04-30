package redis

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisotel"
)

var (
	ErrLocked = errors.New("key already locked")
)

func New(ctx context.Context, conf *config.Config) (rueidis.Client, error) {
	opts := rueidis.ClientOption{
		InitAddress:   []string{conf.Redis.Addr},
		Password:      conf.Redis.Password,
		MaxFlushDelay: conf.Redis.MaxFlushDelay,
	}

	var client rueidis.Client
	var err error
	if *conf.Telemetry.Tracing.Enabled {
		client, err = rueidisotel.NewClient(
			opts,
			rueidisotel.WithDBStatement(func(cmdTokens []string) string {
				return strings.Join(cmdTokens, " ")
			}),
		)
	} else {
		client, err = rueidis.NewClient(opts)
	}

	go checkCanWrite(ctx, client)

	return client, err
}

// Does a write to redis every second to check we can write, if it can't it marks the
// the app as unhealthy
func checkCanWrite(ctx context.Context, client rueidis.Client) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			cmd := client.B().Set().Key("redis:can-write").Value("true").Build()
			if res := client.Do(ctx, cmd); res.Error() != nil {
				logger.Logger(ctx).Error("could not write to redis", "error", res.Error())
				probes.Unhealthy()
				continue
			}
			// Set it back to healthy if it passes
			probes.Healthy()
		}
	}
}
