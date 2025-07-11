FROM golang:1.24 AS gob

ARG version="unknown"

WORKDIR /build

COPY . /build/

RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags="-X main.version=${VERSION}" -a -o api .

FROM alpine:3.22.0

COPY --from=gob /build/api /api
VOLUME [ "/config" ]

ENTRYPOINT [ "/api" ]
