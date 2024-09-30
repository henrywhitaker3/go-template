# Go Template

A template repo for golang APIs, comes with:

- YAML configs
- Postgres db connection
- Atlas/golang-migrate migrations
- Metrics server
- Probes server
- HTTP server
- Test containers setup
- SQLC
- OpenTelemetry Tracing
- Sentry error tracking
- User creation/JWT authentication
- S3/Filesystem storage
- Pryoscope profiling

## Get Started

First, create a new repo from the template, then run:

```
./hack/rename.sh
```

and follow the promts to rename the go module etc.

Then copy the example config file:

```
cp api.example.yaml api.yaml
```

The config file comes with a pre-generated JWT secret and encryption key, you should generate new secrets with:

```
task jwt:secret
task encryption:key
```

## Running Tests

On every PR, the Dockerfile will be built and unit tests will be run, you can run these manually with:

```
task build
```

```
task test:unit
```
