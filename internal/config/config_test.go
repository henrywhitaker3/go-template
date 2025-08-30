package config_test

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/windowframe/crypto"
	"github.com/henrywhitaker3/go-template/internal/jwt"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestItValidates(t *testing.T) {
	tcs := []struct {
		name       string
		config     func(t *testing.T) string
		validates  bool
		assertions func(t *testing.T, conf *config.Config)
	}{
		{
			name: "validates default config",
			config: func(t *testing.T) string {
				return toYaml(t, DefaultConfig(t))
			},
			validates: true,
			assertions: func(t *testing.T, conf *config.Config) {
				require.Equal(t, conf.Name, conf.Telemetry.Profiling.ServiceName)
				require.Equal(t, conf.Name, conf.Telemetry.Tracing.ServiceName)
			},
		},
		{
			name: "it doesnt overwrite default true set to false",
			config: func(t *testing.T) string {
				conf := DefaultConfig(t)
				conf.Database.Enabled = toPtr(false)
				return toYaml(t, conf)
			},
			validates: true,
			assertions: func(t *testing.T, conf *config.Config) {
				require.False(t, *conf.Database.Enabled)
			},
		},
	}

	for _, c := range tcs {
		t.Run(c.name, func(t *testing.T) {
			conf, err := config.Load(c.config(t))
			if c.validates {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
			}
			if c.assertions != nil {
				c.assertions(t, conf)
			}
		})
	}
}

func toPtr[T any](in T) *T {
	return &in
}

func toYaml(t *testing.T, c *config.Config) string {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	by, err := yaml.Marshal(c)
	require.Nil(t, err)
	name := filepath.Join(t.TempDir(), hex.EncodeToString(random))
	require.Nil(t, os.WriteFile(name, by, 0644))
	return name
}

func DefaultConfig(t *testing.T) *config.Config {
	return &config.Config{
		Name:        "go-template",
		Environment: "testing",
		Storage: config.Storage{
			Enabled: toPtr(true),
			Type:    "filesystem",
			Config: map[string]any{
				"dir": t.TempDir(),
			},
		},
		Encryption: config.Encryption{
			Enabled: toPtr(true),
			Secret: must(t, func() (string, error) {
				return crypto.GenerateAesKey(64)
			}),
		},
		Jwt: config.Jwt{
			Enabled: toPtr(true),
			Secret: must(t, func() (string, error) {
				return jwt.GenerateSecret(64)
			}),
		},
		LogLevel: "debug",
		Database: config.Postgres{
			Enabled: toPtr(true),
			Url:     "some_url",
		},
		Redis: config.Redis{
			Enabled: toPtr(true),
			Addr:    "127.0.0.1:0",
		},
		Probes: config.Probes{
			Port: 8766,
		},
		Http: config.Http{
			Port: 8765,
		},
		Queue: config.Queue{
			Enabled: toPtr(true),
		},
		Telemetry: config.Telemetry{
			Metrics: config.Metrics{
				Enabled: toPtr(true),
				Port:    8767,
			},
			Tracing: config.Tracing{
				Enabled:  toPtr(true),
				Endpoint: "bongo",
			},
			Profiling: config.Profiling{
				Enabled:  toPtr(true),
				Endpoint: "bongo",
			},
		},
	}
}

func must[T any](t *testing.T, f func() (T, error)) T {
	out, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
