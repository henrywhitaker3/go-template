package test

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/henrywhitaker3/go-template/internal/queue"
	"github.com/henrywhitaker3/go-template/internal/users"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	root   string
	cancel context.CancelFunc
)

func init() {
	re := regexp.MustCompile(`^(.*go-template)`)
	cwd, _ := os.Getwd()
	rootPath := re.Find([]byte(cwd))
	root = string(rootPath)
}

func User(t *testing.T, b *boiler.Boiler) (*users.User, string) {
	u, err := boiler.Resolve[*users.Users](b)
	require.Nil(t, err)
	password := Sentence(5)

	user, err := u.CreateUser(context.Background(), users.CreateParams{
		Name:     Word(),
		Email:    Email(),
		Password: password,
	})
	require.Nil(t, err)
	return user, password
}

func Token(t *testing.T, b *boiler.Boiler, user *users.User) string {
	require.NotNil(t, user)

	jwt, err := boiler.Resolve[*jwt.Jwt](b)
	require.Nil(t, err)

	token, err := jwt.NewForUser(user, time.Minute)
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
			Logger:  log.TestLogger(t),
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
	require.Contains(
		t,
		string(by),
		"Bucket created successfully",
		"could not create bucket - %s",
		string(by),
	)
}

func RunQueues(t *testing.T, b *boiler.Boiler, ctx context.Context) {
	def, err := boiler.ResolveNamed[*queue.Worker](b, app.DefaultQueue)
	require.Nil(t, err)
	go def.Consume()
	time.Sleep(time.Millisecond * 500)
}

func Must[T any](t *testing.T, f func() (T, error)) T {
	out, err := f()
	require.Nil(t, err)
	return out
}

func ptr[T any](in T) *T {
	return &in
}
