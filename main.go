package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/getsentry/sentry-go"
	"github.com/grafana/pyroscope-go"
	"github.com/henrywhitaker3/boiler"
	"github.com/henrywhitaker3/go-template/cmd/root"
	"github.com/henrywhitaker3/go-template/cmd/secrets"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/windowframe/log"
	"github.com/henrywhitaker3/windowframe/tracing"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version string = "dev"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()

		<-sigs
		fmt.Println("Received seccond interrupt, killing...")
		os.Exit(1)
	}()

	b := boiler.New(ctx)
	defer b.Shutdown()

	// Secret generation utilities that don't need config/app
	if len(os.Args) > 1 && os.Args[1] == "secrets" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		if err := secrets.New().Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	boiler.MustRegister(b, func(*boiler.Boiler) (*config.Config, error) {
		return config.Load(getConfigPath())
	})
	boiler.MustRegister(b, func(b *boiler.Boiler) (*slog.Logger, error) {
		conf, err := boiler.Resolve[*config.Config](b)
		if err != nil {
			return nil, err
		}
		log.Setup(conf.LogLevel.Level())
		return slog.Default(), nil
	})
	b.RegisterSetup(func(b *boiler.Boiler) error {
		_, err := maxprocs.Set(maxprocs.Logger(func(s string, i ...any) {
			slog.Info(fmt.Sprintf(s, i...))
		}))
		return err
	})
	b.RegisterSetup(func(b *boiler.Boiler) error {
		_, err := memlimit.SetGoMemLimitWithOpts(
			memlimit.WithLogger(slog.Default()),
		)
		skip := []error{memlimit.ErrCgroupsNotSupported, memlimit.ErrNoCgroup, memlimit.ErrNoLimit}
		for _, s := range skip {
			if errors.Is(err, s) {
				return nil
			}
		}
		return err
	})

	b.RegisterSetup(func(b *boiler.Boiler) error {
		conf := boiler.MustResolve[*config.Config](b)
		if !*conf.Telemetry.Tracing.Enabled {
			return nil
		}

		slog.Info("tracing enabled", "rate", conf.Telemetry.Tracing.SampleRate)
		tracer, err := tracing.InitTracer(tracing.TracingOpts{
			ServiceName:      conf.Telemetry.Tracing.ServiceName,
			Endpoint:         conf.Telemetry.Tracing.Endpoint,
			Environment:      conf.Environment,
			SampleRate:       conf.Telemetry.Tracing.SampleRate,
			ProfilingEnabled: *conf.Telemetry.Profiling.Enabled,
		}, version)
		if err != nil {
			return fmt.Errorf("setup tracer: %w", err)
		}
		b.RegisterShutdown(func(*boiler.Boiler) error {
			return tracer.Shutdown(context.Background())
		})
		return nil
	})
	b.RegisterSetup(func(b *boiler.Boiler) error {
		conf := boiler.MustResolve[*config.Config](b)
		if !*conf.Telemetry.Sentry.Enabled {
			return nil
		}

		slog.Info("sentry enabled")

		if err := sentry.Init(sentry.ClientOptions{
			Dsn:           conf.Telemetry.Sentry.Dsn,
			Environment:   conf.Environment,
			Release:       version,
			EnableTracing: false,
		}); err != nil {
			return fmt.Errorf("setup sentry: %w", err)
		}
		b.RegisterShutdown(func(*boiler.Boiler) error {
			if ok := sentry.Flush(time.Second * 5); !ok {
				return errors.New("failed to flush sentry")
			}
			return nil
		})
		return nil
	})
	b.RegisterSetup(func(b *boiler.Boiler) error {
		conf := boiler.MustResolve[*config.Config](b)
		if !*conf.Telemetry.Profiling.Enabled {
			return nil
		}

		slog.Info("profiling enabled", "service_name", conf.Telemetry.Profiling.ServiceName)

		host, err := os.Hostname()
		if err != nil {
			return err
		}
		prof, err := pyroscope.Start(pyroscope.Config{
			ApplicationName: conf.Name,
			ServerAddress:   conf.Telemetry.Profiling.Endpoint,
			Logger:          nil,
			Tags: map[string]string{
				"pod":         host,
				"environment": conf.Environment,
				"version":     version,
			},
			ProfileTypes: conf.Telemetry.Profiling.Profilers.PyroscopeTypes(),
		})
		if err != nil {
			return err
		}
		b.RegisterShutdown(func(*boiler.Boiler) error {
			return prof.Stop()
		})
		return nil
	})

	root := root.New(b)
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		os.Exit(2)
	}
}

func getConfigPath() string {
	for i, val := range os.Args {
		if val == "-c" || val == "--config" {
			return os.Args[i+1]
		}
	}
	return "go-template.yaml"
}
