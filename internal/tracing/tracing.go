package tracing

import (
	"context"

	otelpyroscope "github.com/grafana/otel-profiling-go"
	"github.com/henrywhitaker3/go-template/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	otrace "go.opentelemetry.io/otel/trace"
)

var (
	name           = "not set"
	TracerProvider otrace.TracerProvider
)

func InitTracer(conf *config.Config, version string) (*trace.TracerProvider, error) {
	name = conf.Telemetry.Tracing.ServiceName
	var exporter trace.SpanExporter
	var err error
	if conf.Telemetry.Tracing.Endpoint == "stdout" {
		exporter, err = stdout.New(stdout.WithPrettyPrint())
	} else {
		exporter, err = otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpointURL(conf.Telemetry.Tracing.Endpoint),
		)
	}
	if err != nil {
		return nil, err
	}

	res, err := resource.New(
		context.Background(),
		resource.WithContainer(),
		resource.WithOS(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithFromEnv(),
		resource.WithAttributes(
			semconv.ServiceName(name),
			semconv.ServiceVersion(version),
			attribute.String("environment", conf.Environment),
		),
	)
	if err != nil {
		return nil, err
	}

	var ttp otrace.TracerProvider
	tp := trace.NewTracerProvider(
		trace.WithSampler(trace.TraceIDRatioBased(conf.Telemetry.Tracing.SampleRate)),
		trace.WithBatcher(exporter),
		trace.WithResource(res),
	)
	TracerProvider = tp
	if *conf.Telemetry.Profiling.Enabled {
		ttp = otelpyroscope.NewTracerProvider(tp)
	} else {
		ttp = tp
	}

	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)
	otel.SetTracerProvider(ttp)
	return tp, nil
}

func NewSpan(
	ctx context.Context,
	name string,
	opts ...otrace.SpanStartOption,
) (context.Context, otrace.Span) {
	if TracerProvider == nil {
		return otel.Tracer(name).Start(ctx, name, opts...)
	}
	return TracerProvider.Tracer(name).Start(ctx, name, opts...)
}

func AddString(ctx context.Context, key, value string) {
	if span := otrace.SpanFromContext(ctx); span != nil {
		span.SetAttributes(attribute.String(key, value))
	}
}

func TraceID(ctx context.Context) string {
	span := otrace.SpanFromContext(ctx)
	if span.SpanContext().HasTraceID() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}
