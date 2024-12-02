package config

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/grafana/pyroscope-go"
	"github.com/sethvargo/go-envconfig"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type LogLevel string

func (l LogLevel) Level() zap.AtomicLevel {
	switch l {
	case "debug":
		return zap.NewAtomicLevelAt(zap.DebugLevel)
	case "error":
		return zap.NewAtomicLevelAt(zap.ErrorLevel)
	case "info":
		fallthrough
	default:
		return zap.NewAtomicLevelAt(zap.InfoLevel)
	}
}

type Postgres struct {
	Url string `yaml:"url" env:"URL, overwrite"`
}

type Redis struct {
	Addr          string        `yaml:"addr" env:"ADDR, overwrite"`
	Password      string        `yaml:"password" env:"PASSWORD, overwrite"`
	MaxFlushDelay time.Duration `yaml:"max_flush_delay" env:"MAX_FLUSH_DELAY, overwrite, default=100μs"`
}

type Tracing struct {
	ServiceName string  `yaml:"service_name" env:"SERVICE_NAME"`
	Enabled     bool    `yaml:"enabled" env:"ENABLED"`
	SampleRate  float64 `yaml:"sample_rate" env:"SAMPLE_RATE, overwrite, default=1.0"`
	Endpoint    string  `yaml:"endpoint" env:"ENDPOINT"`
}

type Metrics struct {
	Enabled bool `yaml:"enabled" env:"ENABLED"`
	Port    int  `yaml:"port" env:"PORT, overwrite, default=8766"`
}

type Sentry struct {
	Enabled bool   `yaml:"enabled" env:"ENABLED"`
	Dsn     string `yaml:"dsn" env:"DSN"`
}

type Profilers struct {
	CPU           bool `yaml:"cpu" env:"CPU, default=true"`
	AllocObjects  bool `yaml:"alloc_objects" env:"ALLOC_OBJECTS, default=true"`
	AllocSpace    bool `yaml:"alloc_space" env:"ALLOC_SPACE, default=true"`
	InuseObjects  bool `yaml:"inuse_objects" env:"INUSE_OBJECTS"`
	InuseSpace    bool `yaml:"inuse_space" env:"INUSE_SPACE"`
	Goroutines    bool `yaml:"goroutines" env:"GOROUTINES, default=true"`
	BlockCount    bool `yaml:"block_count" env:"BLOCK_COUNT"`
	BlockDuration bool `yaml:"block_duration" env:"BLOCK_DURATION"`
	MutexCount    bool `yaml:"mutex_count" env:"MUTEX_COUNT"`
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
	Enabled     bool   `yaml:"enabled" env:"ENABLED"`
	ServiceName string `yaml:"service_name" env:"SERVICE_NAME"`
	Endpoint    string `yaml:"endpoint" env:"ENDPOINT"`

	Profilers Profilers `yaml:"profilers" env:", prefix=PROFILERS_"`
}

type Telemetry struct {
	Tracing   Tracing   `yaml:"tracing" env:", prefix=TRACING_"`
	Metrics   Metrics   `yaml:"metrics" env:", prefix=METRICS_"`
	Sentry    Sentry    `yaml:"sentry" env:", prefix=SENTRY_"`
	Profiling Profiling `yaml:"profiling" env:", prefix=PROFILING_"`
}

type Probes struct {
	Port int `yaml:"port" env:"PORT, overwrite, default=8767"`
}

type Http struct {
	Port int `yaml:"port" env:"PORT, overwrite, default=8765"`
}

type Storage struct {
	Enabled bool           `yaml:"enabled" env:"ENABLED, default=true"`
	Type    string         `yaml:"type" env:"TYPE"`
	Config  map[string]any `yaml:"config"`
}

type Config struct {
	Name        string `yaml:"name" env:"APP_NAME"`
	Environment string `yaml:"environment" env:"APP_ENV, overwrite, default=dev"`

	Storage Storage `yaml:"storage" env:", prefix=STORAGE_"`

	EncryptionKey string `yaml:"encryption_key" env:"ENCRYPTION_KEY"`
	JwtSecret     string `yaml:"jwt_secret" env:"JWT_SECRET"`

	LogLevel LogLevel `yaml:"log_level" env:"LOG_LEVEL, overwrite, default=error"`
	Database Postgres `yaml:"database" env:", prefix=DB_"`
	Redis    Redis    `yaml:"redis" env:", prefix=REDIS_"`

	Probes Probes `yaml:"probes" env:", prefix=PROBES_"`
	Http   Http   `yaml:"http" env:", prefix=HTTP_"`

	Telemetry Telemetry `yaml:"telemetry" env:", prefix=TELEMETRY_"`
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

	conf.setDefaults()
	if err := conf.validate(); err != nil {
		return nil, err
	}

	if err := envconfig.Process(context.Background(), &conf); err != nil {
		return nil, err
	}

	return &conf, nil
}

func (c *Config) validate() error {
	if c.Database.Url == "" {
		return errors.New("invalid db url")
	}
	if c.Redis.Addr == "" {
		return errors.New("invalid redis addr")
	}
	if c.Name == "" {
		return errors.New("name must be set")
	}
	if c.JwtSecret == "" {
		return errors.New("jwt_secret must be set")
	}
	if c.EncryptionKey == "" {
		return errors.New("encryption_key must be set")
	}
	if c.Telemetry.Sentry.Enabled && c.Telemetry.Sentry.Dsn == "" {
		return errors.New("sentry dsn must be set when enabled")
	}
	if c.Telemetry.Profiling.Enabled && c.Telemetry.Profiling.Endpoint == "" {
		return errors.New("profiling endpoint must be set when enabled")
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
