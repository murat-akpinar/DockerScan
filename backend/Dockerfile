FROM golang:1.25-alpine AS build

WORKDIR /app

ENV GOPROXY=https://proxy.golang.org,direct \
    GONOSUMDB=*

RUN apk update && apk upgrade --no-cache && apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o /DockScan-backend ./...

FROM alpine:3.22 AS runtime

WORKDIR /app

RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata wget && \
    apk fix --no-cache && \
    rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

RUN addgroup -S app && adduser -S app -G app

COPY --from=build /DockScan-backend /usr/local/bin/DockScan-backend

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:8080/health || exit 1

CMD ["DockScan-backend"]
