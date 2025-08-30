package test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/config"
	pg "github.com/henrywhitaker3/windowframe/database/postgres"
	wlog "github.com/henrywhitaker3/windowframe/log"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	boil *boiler.Boiler
)

func Boiler(t *testing.T, recreate ...bool) *boiler.Boiler {
	if len(recreate) > 0 {
		t.Log("creating new boiler")
		return newBoiler(t)
	}

	if boil == nil {
		t.Log("no boiler yet, making a new one")
		boil = newBoiler(t)
	}

	return boil
}

type testingWriter struct {
	t *testing.T
}

func (t testingWriter) Write(in []byte) (int, error) {
	t.t.Log(string(in))
	return len(in), nil
}

func newBoiler(t *testing.T) *boiler.Boiler {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)

	b := boiler.New(ctx)

	t.Log("spinning up postgres container")
	wlog.Setup(slog.LevelDebug, testingWriter{t: t})
	pgCont, err := postgres.Run(
		ctx,
		"postgres:17",
		testcontainers.WithLogger(log.TestLogger(t)),
		postgres.WithDatabase("orderly"),
		postgres.WithUsername("orderly"),
		postgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second)),
	)
	require.Nil(t, err)

	conf, err := config.Load(fmt.Sprintf("%s/go-template.example.yaml", root))
	require.Nil(t, err)
	conn, err := pgCont.ConnectionString(context.Background())
	require.Nil(t, err)
	conf.Database.Url = conn

	t.Log("spinning up redis container")
	redisCont, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "ghcr.io/dragonflydb/dragonfly:latest",
				ExposedPorts: []string{"6379/tcp"},
				WaitingFor:   wait.ForListeningPort("6379/tcp"),
				Cmd: []string{
					"--proactor_threads=1",
					"--default_lua_flags=allow-undeclared-keys",
				},
			},
			Started: true,
			Logger:  log.TestLogger(t),
		},
	)
	require.Nil(t, err)
	redisHost, err := redisCont.Host(ctx)
	require.Nil(t, err)
	redisPort, err := redisCont.MappedPort(ctx, nat.Port("6379"))
	require.Nil(t, err)
	conf.Redis.Addr = fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

	conf.Environment = "testing"

	conf.Storage.Enabled = ptr(true)
	conf.Storage.Type = "s3"
	conf.Storage.Config = map[string]any{
		"region":     "test",
		"bucket":     strings.ToLower(Letters(10)),
		"access_key": Sentence(3),
		"secret_key": Sentence(3),
		"insecure":   true,
	}

	t.Log("spinning up minio")
	minio(t, &conf.Storage, ctx)

	require.Nil(t, boiler.Register[*config.Config](b, func(*boiler.Boiler) (*config.Config, error) {
		return conf, nil
	}))

	app.RegisterServe(b)

	t.Log("bootstrapping boiler")
	require.Nil(t, b.Bootstrap())
	t.Log("finished bootstrap")

	mig := boiler.MustResolve[*pg.Migrator](b)
	require.Nil(t, err)
	t.Log("running migrations")
	require.Nil(t, mig.Up())

	b.RegisterShutdown(func(*boiler.Boiler) error {
		redisCont.Terminate(context.Background())
		pgCont.Terminate(context.Background())
		cancel()
		return nil
	})

	return b
}
