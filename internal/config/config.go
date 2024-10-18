package config

import (
	"errors"
	"os"
	"time"

	"github.com/grafana/pyroscope-go"
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
	Url string `yaml:"url"`
}

type Redis struct {
	Addr          string        `yaml:"addr"`
	Password      string        `yaml:"password"`
	MaxFlushDelay time.Duration `yaml:"max_flush_delay"`
}

type Tracing struct {
	ServiceName string  `yaml:"service_name"`
	Enabled     bool    `yaml:"enabled"`
	SampleRate  float64 `yaml:"sample_rate"`
	Endpoint    string  `yaml:"endpoint"`
}

type Metrics struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type Sentry struct {
	Enabled bool   `yaml:"enabled"`
	Dsn     string `yaml:"dsn"`
}

type Profilers struct {
	CPU           bool `yaml:"cpu"`
	AllocObjects  bool `yaml:"alloc_objects"`
	AllocSpace    bool `yaml:"alloc_space"`
	InuseObjects  bool `yaml:"inuse_objects"`
	InuseSpace    bool `yaml:"inuse_space"`
	Goroutines    bool `yaml:"goroutines"`
	BlockCount    bool `yaml:"block_count"`
	BlockDuration bool `yaml:"block_duration"`
	MutexCount    bool `yaml:"mutex_count"`
	MutexDuration bool `yaml:"mutex_duration"`
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
	Enabled     bool   `yaml:"enabled"`
	ServiceName string `yaml:"service_name"`
	Endpoint    string `yaml:"endpoint"`

	Profilers Profilers `yaml:"profilers"`
}

type Telemetry struct {
	Tracing   Tracing   `yaml:"tracing"`
	Metrics   Metrics   `yaml:"metrics"`
	Sentry    Sentry    `yaml:"sentry"`
	Profiling Profiling `yaml:"profiling"`
}

type Probes struct {
	Port int `yaml:"port"`
}

type Http struct {
	Port int `yaml:"port"`
}

type Storage struct {
	Enabled bool           `yaml:"enabled"`
	Type    string         `yaml:"type"`
	Config  map[string]any `yaml:"config"`
}

type Config struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`

	Storage Storage `yaml:"storage"`

	EncryptionKey string `yaml:"encryption_key"`
	JwtSecret     string `yaml:"jwt_secret"`

	LogLevel LogLevel `yaml:"log_level"`
	Database Postgres `yaml:"database"`
	Redis    Redis    `yaml:"redis"`

	Probes Probes `yaml:"probes"`
	Http   Http   `yaml:"http"`

	Telemetry Telemetry `yaml:"telemetry"`
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
	if c.Environment == "" {
		c.Environment = "dev"
	}
	if c.Redis.MaxFlushDelay == 0 {
		c.Redis.MaxFlushDelay = time.Microsecond * 100
	}
	if c.Http.Port == 0 {
		c.Http.Port = 8765
	}
	if c.Telemetry.Metrics.Port == 0 {
		c.Telemetry.Metrics.Port = 8766
	}
	if c.Probes.Port == 0 {
		c.Probes.Port = 8767
	}
	if c.Telemetry.Tracing.ServiceName == "" {
		c.Telemetry.Tracing.ServiceName = c.Name
	}
	if c.Telemetry.Profiling.ServiceName == "" {
		c.Telemetry.Profiling.ServiceName = c.Name
	}
}
