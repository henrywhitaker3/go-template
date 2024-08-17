package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/henrywhitaker3/go-template/cmd/root"
	"github.com/henrywhitaker3/go-template/cmd/secrets"
	"github.com/henrywhitaker3/go-template/internal/app"
	"github.com/henrywhitaker3/go-template/internal/config"
	"github.com/henrywhitaker3/go-template/internal/http"
	"github.com/henrywhitaker3/go-template/internal/logger"
	"github.com/henrywhitaker3/go-template/internal/tracing"
)

var (
	version string = "dev"
)

func main() {
	// Secret generation utlities that dont need config/app
	if len(os.Args) > 1 && os.Args[1] == "secrets" {
		os.Args = append(os.Args[:1], os.Args[2:]...)
		if err := secrets.New().Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	conf, err := config.Load(getConfigPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			noConfigHelp()
		}
		die(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()

		<-sigs
		die(errors.New("received second interrupt"))
	}()

	logger.Wrap(ctx, conf.LogLevel.Level())
	logger := logger.Logger(ctx)
	defer logger.Sync()

	if conf.Telemetry.Tracing.Enabled {
		logger.Infow("otel tracing enabled", "service_name", conf.Telemetry.Tracing.ServiceName)
		tracer, err := tracing.InitTracer(conf, version)
		if err != nil {
			die(err)
		}
		defer tracer.Shutdown(context.Background())
	}
	if conf.Telemetry.Sentry.Enabled {
		logger.Info("sentry enabled")
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:           conf.Telemetry.Sentry.Dsn,
			Environment:   conf.Environment,
			Release:       version,
			EnableTracing: false,
		}); err != nil {
			die(err)
		}
		defer sentry.Flush(time.Second * 2)
	}

	app, err := app.New(ctx, conf)
	if err != nil {
		die(err)
	}
	app.Version = version
	app.Http = http.New(app)

	root := root.New(app)
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

func noConfigHelp() {
	help := `Usage:
	api [command]

Flags:
	-c, --config	The path to the api config file (default: go-template.yaml)
	`
	fmt.Println(help)
	os.Exit(3)
}

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}
