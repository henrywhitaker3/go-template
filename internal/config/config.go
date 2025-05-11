package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/sethvargo/go-envconfig"
	"gopkg.in/yaml.v3"
)

type LogLevel string

func (l LogLevel) Level() slog.Level {
	switch l {
	case "debug":
		return slog.LevelDebug
	case "error":
		return slog.LevelError
	case "info":
		fallthrough
	default:
		return slog.LevelInfo
	}
}

type Postgres struct {
	Enabled    *bool  `yaml:"enabled"      env:"ENABLED, overwrite, default=true"`
	Url        string `yaml:"url"          env:"URL, overwrite"`
	Host       string `yaml:"host"         env:"HOST, overwrite"`
	Port       int    `yaml:"port"         env:"PORT, overwrite"`
	Database   string `yaml:"database"     env:"DATABASE, overwrite"`
	User       string `yaml:"user"         env:"USER, overwrite"`
	Password   string `yaml:"password"     env:"PASSWORD, overwrite"`
	SslMode    string `yaml:"ssl_mode"     env:"SSL_MODE, overwrite"`
	CaCertFile string `yaml:"ca_cert_file" env:"CA_CERT_FILE, overwrite"`
}

func (p Postgres) Uri() string {
	url := ""
	if p.Url != "" {
		url = strings.Split(p.Url, "?")[0]
	} else {
		url = fmt.Sprintf("postgresql://%s:%s@%s:%d/%s", p.User, p.Password, p.Host, p.Port, p.Database)
	}
	args := []string{}
	if p.SslMode != "" {
		args = append(args, fmt.Sprintf("sslmode=%s", p.SslMode))
	}
	if p.CaCertFile != "" {
		args = append(args, fmt.Sprintf("sslrootcert=%s", p.CaCertFile))
	}
	if len(args) > 0 {
		url = fmt.Sprintf("%s?%s", url, strings.Join(args, "&"))
	}
	return url
}

type Redis struct {
	Enabled       *bool         `yaml:"enabled"         env:"ENABLED, overwrite, default=true"`
	Addr          string        `yaml:"addr"            env:"ADDR, overwrite"`
	Password      string        `yaml:"password"        env:"PASSWORD, overwrite"`
	MaxFlushDelay time.Duration `yaml:"max_flush_delay" env:"MAX_FLUSH_DELAY, overwrite, default=100μs"`
}

type Tracing struct {
	ServiceName string  `yaml:"service_name" env:"SERVICE_NAME"`
	Enabled     *bool   `yaml:"enabled"      env:"ENABLED"`
	SampleRate  float64 `yaml:"sample_rate"  env:"SAMPLE_RATE, overwrite, default=1.0"`
	Endpoint    string  `yaml:"endpoint"     env:"ENDPOINT"`
}

type Metrics struct {
	Enabled *bool `yaml:"enabled" env:"ENABLED, overwrite, default=true"`
	Port    int   `yaml:"port"    env:"PORT, overwrite, default=8766"`
}

type Sentry struct {
	Enabled *bool  `yaml:"enabled" env:"ENABLED, overwrite, default=false"`
	Dsn     string `yaml:"dsn"     env:"DSN"`
}

type Profilers struct {
	CPU           bool `yaml:"cpu"            env:"CPU, default=true"`
	AllocObjects  bool `yaml:"alloc_objects"  env:"ALLOC_OBJECTS, default=true"`
	AllocSpace    bool `yaml:"alloc_space"    env:"ALLOC_SPACE, default=true"`
	InuseObjects  bool `yaml:"inuse_objects"  env:"INUSE_OBJECTS"`
	InuseSpace    bool `yaml:"inuse_space"    env:"INUSE_SPACE"`
	Goroutines    bool `yaml:"goroutines"     env:"GOROUTINES, default=true"`
	BlockCount    bool `yaml:"block_count"    env:"BLOCK_COUNT"`
	BlockDuration bool `yaml:"block_duration" env:"BLOCK_DURATION"`
	MutexCount    bool `yaml:"mutex_count"    env:"MUTEX_COUNT"`
	MutexDuration bool `yaml:"mutex_duration" env:"MUTEX_DURATION"`
}

func (p Profilers) PyroscopeTypes() []pyroscope.ProfileType {
	out := []pyroscope.ProfileType{}
	if p.CPU {
		out = append(out, pyroscope.ProfileCPU)
	}
	if p.AllocObjects {
		out = append(out, pyroscope.ProfileAllocObjects)
	}
	if p.AllocSpace {
		out = append(out, pyroscope.ProfileInuseSpace)
	}
	if p.InuseObjects {
		out = append(out, pyroscope.ProfileInuseObjects)
	}
	if p.InuseSpace {
		out = append(out, pyroscope.ProfileInuseSpace)
	}
	if p.Goroutines {
		out = append(out, pyroscope.ProfileGoroutines)
	}
	if p.BlockCount {
		out = append(out, pyroscope.ProfileBlockCount)
	}
	if p.BlockDuration {
		out = append(out, pyroscope.ProfileBlockDuration)
	}
	if p.MutexCount {
		out = append(out, pyroscope.ProfileMutexCount)
	}
	if p.MutexDuration {
		out = append(out, pyroscope.ProfileMutexDuration)
	}
	return out
}

type Profiling struct {
	Enabled     *bool  `yaml:"enabled"      env:"ENABLED, overwrite, default=false"`
	ServiceName string `yaml:"service_name" env:"SERVICE_NAME"`
	Endpoint    string `yaml:"endpoint"     env:"ENDPOINT"`

	Profilers Profilers `yaml:"profilers" env:", prefix=PROFILERS_"`
}

type Telemetry struct {
	Tracing   Tracing   `yaml:"tracing"   env:", prefix=TRACING_"`
	Metrics   Metrics   `yaml:"metrics"   env:", prefix=METRICS_"`
	Sentry    Sentry    `yaml:"sentry"    env:", prefix=SENTRY_"`
	Profiling Profiling `yaml:"profiling" env:", prefix=PROFILING_"`
}

type Probes struct {
	Port int `yaml:"port" env:"PORT, overwrite, default=8767"`
}

type Http struct {
	Port int `yaml:"port" env:"PORT, overwrite, default=8765"`
}

type Storage struct {
	Enabled *bool          `yaml:"enabled" env:"ENABLED, default=true"`
	Type    string         `yaml:"type"    env:"TYPE"`
	Config  map[string]any `yaml:"config"`
}

type Jwt struct {
	Enabled *bool  `yaml:"enabled" env:"ENABLED, overwrite, default=true"`
	Secret  string `yaml:"secret"  env:"SECRET, overwrite"`
}

type Encryption struct {
	Enabled *bool  `yaml:"enabled" env:"ENABLED, overwrite, default=true"`
	Secret  string `yaml:"secret"  env:"SECRET, overwrite"`
}

type Queue struct {
	Enabled     *bool `yaml:"enabled"     env:"ENABLED, overwrite, default=true"`
	DB          int   `yaml:"db"          env:"DB, overwrite, default=5"`
	Concurrency *int  `yaml:"concurrency" env:"CONCURRENCY, overwrite"`
}

type Runner struct {
	Enabled *bool `yaml:"enabled" env:"ENABLED, overwrite, default=true"`
}

type Config struct {
	Name        string `yaml:"name"        env:"APP_NAME"`
	Environment string `yaml:"environment" env:"APP_ENV, overwrite, default=dev"`

	Storage Storage `yaml:"storage" env:", prefix=STORAGE_"`

	Encryption Encryption `yaml:"encryption" env:", prefix=ENCRYPTION"`
	Jwt        Jwt        `yaml:"jwt"        env:", prefix=JWT_"`

	LogLevel LogLevel `yaml:"log_level" env:"LOG_LEVEL, overwrite, default=error"`
	Database Postgres `yaml:"database"  env:", prefix=DB_"`
	Redis    Redis    `yaml:"redis"     env:", prefix=REDIS_"`

	Probes Probes `yaml:"probes" env:", prefix=PROBES_"`
	Http   Http   `yaml:"http"   env:", prefix=HTTP_"`

	Telemetry Telemetry `yaml:"telemetry" env:", prefix=TELEMETRY_"`

	Queue  Queue  `yaml:"queue"  env:", prefix=QUEUE_"`
	Runner Runner `yaml:"runner" env:", prefix=RUNNER_"`
}

func Load(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf Config
	if err := yaml.Unmarshal(file, &conf); err != nil {
		return nil, err
	}

	if err := envconfig.Process(context.Background(), &conf); err != nil {
		return nil, err
	}

	conf.setDefaults()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}

func (c *Config) validate() error {
	if c.Database.Uri() == "" {
		return errors.New("invalid db url")
	}
	if c.Redis.Addr == "" {
		return errors.New("invalid redis addr")
	}
	if c.Name == "" {
		return errors.New("name must be set")
	}
	if *c.Jwt.Enabled && c.Jwt.Secret == "" {
		return errors.New("jwt secret must be set")
	}
	if *c.Encryption.Enabled && c.Encryption.Secret == "" {
		return errors.New("encryption secret must be set")
	}
	if *c.Telemetry.Sentry.Enabled && c.Telemetry.Sentry.Dsn == "" {
		return errors.New("sentry dsn must be set when enabled")
	}
	if *c.Telemetry.Profiling.Enabled && c.Telemetry.Profiling.Endpoint == "" {
		return errors.New("profiling endpoint must be set when enabled")
	}
	if !(*c.Redis.Enabled) && *c.Queue.Enabled {
		return errors.New("queue cannot be enabled without redis")
	}
	if !(*c.Redis.Enabled) && *c.Runner.Enabled {
		return errors.New("runner cannot be enabled without redis")
	}
	return nil
}

func (c *Config) setDefaults() {
	if c.Telemetry.Tracing.ServiceName == "" {
		c.Telemetry.Tracing.ServiceName = c.Name
	}
	if c.Telemetry.Profiling.ServiceName == "" {
		c.Telemetry.Profiling.ServiceName = c.Name
	}
}
