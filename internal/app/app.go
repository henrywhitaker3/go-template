package app

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/henrywhitaker3/boiler"
	gocache "github.com/henrywhitaker3/go-cache"
	"github.com/henrywhitaker3/go-template/database/queries"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/windowframe/crypto"
	ohttp "github.com/henrywhitaker3/go-template/internal/http"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/metrics"
	"github.com/henrywhitaker3/go-template/internal/postgres"
	iprobes "github.com/henrywhitaker3/go-template/internal/probes"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/henrywhitaker3/go-template/internal/redis"
	"github.com/henrywhitaker3/go-template/internal/storage"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/henrywhitaker3/probes"
	"github.com/henrywhitaker3/windowframe/workers"
	"github.com/redis/rueidis"
	"github.com/thanos-io/objstore"
)

func RegisterServe(b *boiler.Boiler) {
	RegisterBase(b)
	boiler.MustRegister(b, RegisterRunner)
	boiler.MustRegister(b, RegisterHTTP)
}

func RegisterBase(b *boiler.Boiler) {
	conf := boiler.MustResolve[*config.Config](b)

	boiler.MustRegister(b, RegisterProbes)
	boiler.MustRegister(b, RegisterProbesServer)
	if *conf.Telemetry.Metrics.Enabled {
		boiler.MustRegister(b, RegisterMetrics)
	}
	if *conf.Database.Enabled {
		boiler.MustRegister(b, RegisterDB)
		boiler.MustRegister(b, RegisterQueries)
		boiler.MustRegister(b, RegisterMigrator)
	}
	if *conf.Redis.Enabled {
		boiler.MustRegister(b, RegisterRedis)
		boiler.MustRegister(b, RegisterCache)
	}
	if *conf.Jwt.Enabled {
		boiler.MustRegister(b, RegisterJWT)
	}
	if *conf.Encryption.Enabled {
		boiler.MustRegister(b, RegisterEncryption)
	}
	if *conf.Storage.Enabled {
		boiler.MustRegister(b, RegisterStorage)
	}
	boiler.MustRegisterDeferred(b, RegisterUsers)
	if *conf.Queue.Enabled {
		boiler.MustRegister(b, RegisterQueue)
	}
}

func RegisterConsumers(b *boiler.Boiler) {
	RegisterBase(b)
	boiler.MustRegisterNamedDefered(b, DefaultQueue, RegisterDefaultQueueWorker)
}

func RegisterDB(b *boiler.Boiler) (*sql.DB, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	db, err := postgres.Open(b.Context(), conf.Database.Uri(), conf.Telemetry.Tracing)
	if err != nil {
		return nil, err
	}
	b.RegisterShutdown(func(b *boiler.Boiler) error {
		return db.Close()
	})
	return db, nil
}

func RegisterMigrator(b *boiler.Boiler) (*postgres.Migrator, error) {
	db, err := boiler.Resolve[*sql.DB](b)
	if err != nil {
		return nil, err
	}

	return postgres.NewMigrator(db)
}

func RegisterRedis(b *boiler.Boiler) (rueidis.Client, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	redis, err := redis.New(b.Context(), conf)
	if err != nil {
		return nil, err
	}
	b.RegisterShutdown(func(b *boiler.Boiler) error {
		redis.Close()
		return nil
	})
	return redis, nil
}

func RegisterCache(b *boiler.Boiler) (*gocache.Cache, error) {
	redis, err := boiler.Resolve[rueidis.Client](b)
	if err != nil {
		return nil, err
	}
	return gocache.NewCache(
		gocache.NewRueidisStore(redis),
	), nil
}

func RegisterQueries(b *boiler.Boiler) (*queries.Queries, error) {
	db, err := boiler.Resolve[*sql.DB](b)
	if err != nil {
		return nil, err
	}
	return queries.New(db), nil
}

func RegisterUsers(b *boiler.Boiler) (*users.Users, error) {
	q, err := boiler.Resolve[*queries.Queries](b)
	if err != nil {
		return nil, err
	}
	return users.New(q), nil
}

func RegisterJWT(b *boiler.Boiler) (*jwt.Jwt, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	return jwt.New(conf.Jwt.Secret), nil
}

func RegisterHTTP(b *boiler.Boiler) (*ohttp.Http, error) {
	return ohttp.New(b), nil
}

func RegisterEncryption(b *boiler.Boiler) (*crypto.Encrptor, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	return crypto.NewEncryptor(conf.Encryption.Secret)
}

func RegisterProbes(b *boiler.Boiler) (*probes.Probes, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	p := iprobes.New(conf.Probes.Port)
	iprobes.Probes = p
	b.RegisterSetup(func(b *boiler.Boiler) error {
		return p.Ready(iprobes.App)
	})
	b.RegisterShutdown(func(b *boiler.Boiler) error {
		return p.NotReady(iprobes.App)
	})
	return p, nil
}

func RegisterProbesServer(b *boiler.Boiler) (*probes.Server, error) {
	p, err := boiler.Resolve[*probes.Probes](b)
	if err != nil {
		return nil, err
	}
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	srv := probes.NewServer(probes.ServerOpts{
		Addr:   fmt.Sprintf(":%d", conf.Probes.Port),
		Probes: p,
	})
	b.RegisterSetup(func(b *boiler.Boiler) error {
		go func() {
			slog.Info("starting probes server", "port", conf.Probes.Port)
			if err := srv.Start(); err != nil {
				if !errors.Is(err, http.ErrServerClosed) {
					slog.Error("failed to start probes server", "error", err)
				}
			}
		}()
		return nil
	})
	b.RegisterShutdown(func(b *boiler.Boiler) error {
		return srv.Shutdown(b.Context())
	})

	return srv, nil
}

func RegisterMetrics(b *boiler.Boiler) (*metrics.Metrics, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	return metrics.New(conf.Telemetry.Metrics.Port), nil
}

func RegisterQueue(b *boiler.Boiler) (*queue.Publisher, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	return queue.NewPublisher(queue.PublisherOpts{
		Redis: queue.RedisOpts{
			Addr:        conf.Redis.Addr,
			Password:    conf.Redis.Password,
			DB:          conf.Queue.DB,
			OtelEnabled: *conf.Telemetry.Tracing.Enabled,
		},
	})
}

func RegisterRunner(b *boiler.Boiler) (*workers.Runner, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	redis, err := boiler.Resolve[rueidis.Client](b)
	if err != nil {
		return nil, err
	}
	met, err := boiler.Resolve[*metrics.Metrics](b)
	if err != nil {
		return nil, err
	}
	work, err := workers.NewRunner(b.Context(), workers.RunnerOpts{
		Redis:  redis,
		Logger: slog.Default(),
		Monitor: workers.MonitorOpts{
			Namespace: strings.ToLower(strings.ReplaceAll(conf.Name, " ", "_")),
		},
		Registerer: met.Registry,
	})
	if err != nil {
		return nil, err
	}

	db, err := boiler.Resolve[*queries.Queries](b)
	if err != nil {
		return nil, err
	}

	if err := work.Register(users.NewExpirer(db)); err != nil {
		return nil, err
	}

	return work, nil
}

func RegisterStorage(b *boiler.Boiler) (objstore.Bucket, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	return storage.New(conf.Storage)
}

const (
	DefaultQueue = "queue:default"
)

func RegisterDefaultQueueWorker(
	b *boiler.Boiler,
) (*queue.Worker, error) {
	conf, err := boiler.Resolve[*config.Config](b)
	if err != nil {
		return nil, err
	}
	conc := 0
	if conf.Queue.Concurrency != nil {
		conc = *conf.Queue.Concurrency
	}
	return queue.NewWorker(b.Context(), queue.ServerOpts{
		Redis: queue.RedisOpts{
			Addr:        conf.Redis.Addr,
			Password:    conf.Redis.Password,
			DB:          conf.Queue.DB,
			OtelEnabled: *conf.Telemetry.Tracing.Enabled,
		},
		Queues:      []queue.Queue{queue.DefaultQueue},
		Concurrency: conc,
	})
}
