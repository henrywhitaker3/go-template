package app

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	gocache "github.com/henrywhitaker3/go-cache"
	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/crypto"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/postgres"
	"github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/henrywhitaker3/go-template/internal/redis"
	"github.com/henrywhitaker3/go-template/internal/storage"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/go-template/internal/workers"
	"github.com/labstack/echo/v4"
	"github.com/redis/rueidis"
	"github.com/thanos-io/objstore"
)

type server interface {
	Start(context.Context) error
	Stop(context.Context) error
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	Routes() []*echo.Route
}

type App struct {
	Version string

	Config *config.Config

	Http server

	Probes  *probes.Probes
	Metrics *metrics.Metrics

	Runner *workers.Runner

	Users *users.Users

	Jwt        *jwt.Jwt
	Encryption *crypto.Encrptor

	Database *sql.DB
	Queries  *queries.Queries
	Redis    rueidis.Client
	Storage  objstore.Bucket
	Cache    *gocache.Cache
	Queue    *queue.Publisher
}

func New(ctx context.Context, conf *config.Config) (*App, error) {
	probes := probes.New(conf.Probes.Port)
	redis, err := redis.New(ctx, conf)
	if err != nil {
		return nil, err
	}

	db, err := postgres.Open(ctx, conf.Database, conf.Telemetry.Tracing)
	if err != nil {
		return nil, err
	}
	queries := queries.New(db)

	enc, err := crypto.NewEncryptor(conf.EncryptionKey)
	if err != nil {
		return nil, err
	}

	runner, err := workers.NewRunner(ctx, redis)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise runner: %w", err)
	}

	pub, err := queue.NewPublisher(queue.PublisherOpts{
		Redis: queue.RedisOpts{
			Addr:        conf.Redis.Addr,
			Password:    conf.Redis.Password,
			DB:          conf.Queue.DB,
			OtelEnabled: conf.Telemetry.Tracing.Enabled,
		},
	})
	if err != nil {
		return nil, err
	}

	app := &App{
		Config: conf,

		Database: db,
		Queries:  queries,
		Redis:    redis,
		Cache:    gocache.NewCache(gocache.NewRueidisStore(redis)),

		Users: users.New(queries),

		Encryption: enc,
		Jwt:        jwt.New(conf.JwtSecret, redis),

		Probes:  probes,
		Metrics: metrics.New(conf.Telemetry.Metrics.Port),

		Runner: runner,
		Queue:  pub,
	}

	if conf.Storage.Enabled {
		storage, err := storage.New(conf.Storage)
		if err != nil {
			return nil, err
		}
		app.Storage = storage
	}

	return app, nil
}

func (a *App) Worker(ctx context.Context, queues []queue.Queue) (*queue.Worker, error) {
	return queue.NewWorker(ctx, queue.ServerOpts{
		Redis: queue.RedisOpts{
			Addr:        a.Config.Redis.Addr,
			Password:    a.Config.Redis.Password,
			DB:          a.Config.Queue.DB,
			OtelEnabled: a.Config.Telemetry.Tracing.Enabled,
		},
		Queues: queues,
	})
}
