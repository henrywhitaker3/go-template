package test

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http"
	"github.com/henrywhitaker3/go-template/internal/logger"
	pg "github.com/henrywhitaker3/go-template/internal/postgres"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	root   string
	a      *app.App
	cancel context.CancelFunc
)

func init() {
	re := regexp.MustCompile(`^(.*go-template)`)
	cwd, _ := os.Getwd()
	rootPath := re.Find([]byte(cwd))
	root = string(rootPath)
}

// Added variadic bool so as to not introduce breaking change
func App(t *testing.T, new ...bool) (*app.App, context.CancelFunc) {
	recreate := false
	if len(new) > 0 && new[0] {
		recreate = true
	}

	if recreate {
		return newApp(t)
	}

	if a == nil {
		a, cancel = newApp(t)
	}

	return a, func() {
		// We're sharing the app here between tests, so we don't want them
		// being cancelled in any tests that use the shared app
	}
}

func newApp(t *testing.T) (*app.App, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)

	logger.Wrap(ctx, zap.NewAtomicLevelAt(zapcore.DebugLevel))
	pgCont, err := postgres.Run(
		ctx,
		"postgres:16",
		testcontainers.WithLogger(testcontainers.TestLogger(t)),
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

	redisCont, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "ghcr.io/dragonflydb/dragonfly:latest",
				ExposedPorts: []string{"6379/tcp"},
				WaitingFor:   wait.ForListeningPort("6379/tcp"),
				Cmd:          []string{"--proactor_threads=1", "--default_lua_flags=allow-undeclared-keys"},
			},
			Started: true,
			Logger:  testcontainers.TestLogger(t),
		},
	)
	require.Nil(t, err)
	redisHost, err := redisCont.Host(ctx)
	require.Nil(t, err)
	redisPort, err := redisCont.MappedPort(ctx, nat.Port("6379"))
	require.Nil(t, err)
	conf.Redis.Addr = fmt.Sprintf("%s:%d", redisHost, redisPort.Int())

	conf.Environment = "testing"

	conf.Storage.Enabled = true
	conf.Storage.Type = "s3"
	conf.Storage.Config = map[string]any{
		"region":     "test",
		"bucket":     strings.ToLower(Letters(10)),
		"access_key": Sentence(3),
		"secret_key": Sentence(3),
		"insecure":   true,
	}

	minio(t, &conf.Storage, ctx)
	t.Log(conf.Storage)

	app, err := app.New(ctx, conf)
	require.Nil(t, err)

	app.Http = http.New(app)

	mig, err := pg.NewMigrator(app.Database)
	require.Nil(t, err)

	require.Nil(t, mig.Up())

	return app, func() {
		require.Nil(t, redisCont.Terminate(ctx))
		require.Nil(t, pgCont.Terminate(ctx))
		cancel()
	}
}

func User(t *testing.T, app *app.App) (*users.User, string) {
	require.NotNil(t, app)

	password := Sentence(5)

	user, err := app.Users.CreateUser(context.Background(), users.CreateParams{
		Name:     Word(),
		Email:    Email(),
		Password: password,
	})
	require.Nil(t, err)
	return user, password
}

func Token(t *testing.T, app *app.App, user *users.User) string {
	require.NotNil(t, app)
	require.NotNil(t, user)

	token, err := app.Jwt.NewForUser(user, time.Minute)
	require.Nil(t, err)
	return token
}

func minio(t *testing.T, conf *config.Storage, ctx context.Context) {
	minio, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "quay.io/minio/minio:latest",
				ExposedPorts: []string{"9000/tcp"},
				WaitingFor:   wait.ForListeningPort("9000/tcp"),
				Cmd:          []string{"server", "/data"},
				Env: map[string]string{
					"MINIO_ROOT_USER":     conf.Config["access_key"].(string),
					"MINIO_ROOT_PASSWORD": conf.Config["secret_key"].(string),
					"MINIO_REGION":        "test",
				},
			},
			Started: true,
			Logger:  testcontainers.TestLogger(t),
		},
	)
	require.Nil(t, err)

	host, err := minio.Host(ctx)
	require.Nil(t, err)
	port, err := minio.MappedPort(ctx, nat.Port("9000/tcp"))
	require.Nil(t, err)
	conf.Config["endpoint"] = fmt.Sprintf("%s:%d", host, port.Int())

	// Now create the bucket using mc
	// init, err :=
	_, output, err := minio.Exec(ctx, []string{
		"/bin/sh",
		"-c",
		fmt.Sprintf(`/usr/bin/mc alias set minio http://127.0.0.1:9000 "%s" "%s";
/usr/bin/mc mb minio/%s
		`, conf.Config["access_key"].(string), conf.Config["secret_key"].(string), conf.Config["bucket"].(string)),
	})
	require.Nil(t, err)
	by, err := io.ReadAll(output)
	require.Nil(t, err)
	require.Contains(t, string(by), "Bucket created successfully", "could not create bucket - %s", string(by))
}

func RunQueues(t *testing.T, app *app.App, ctx context.Context) {
	worker, err := app.Worker(ctx, []queue.Queue{queue.DefaultQueue})
	require.Nil(t, err)
	go worker.Consume()
	time.Sleep(time.Millisecond * 500)
}
