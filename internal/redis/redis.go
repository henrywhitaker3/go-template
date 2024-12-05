package redis

import (
	"errors"
	"strings"

	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/redis/rueidis"
	"github.com/redis/rueidis/rueidisotel"
)

var (
	ErrLocked = errors.New("key already locked")
)

func New(conf *config.Config) (rueidis.Client, error) {
	opts := rueidis.ClientOption{
		InitAddress:   []string{conf.Redis.Addr},
		Password:      conf.Redis.Password,
		MaxFlushDelay: conf.Redis.MaxFlushDelay,
	}

	var client rueidis.Client
	var err error
	if conf.Telemetry.Tracing.Enabled {
		client, err = rueidisotel.NewClient(opts, rueidisotel.WithDBStatement(func(cmdTokens []string) string {
			return strings.Join(cmdTokens, " ")
		}))
	} else {
		client, err = rueidis.NewClient(opts)
	}

	return client, err
}
