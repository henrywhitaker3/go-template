FROM golang:1.23 AS gob

ARG version="unknown"

WORKDIR /build

COPY . /build/

RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags="-X main.version=${VERSION}" -a -o api main.go

FROM alpine:3.21.3

COPY --from=gob /build/api /api
VOLUME [ "/config" ]

ENTRYPOINT [ "/api" ]
