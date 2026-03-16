# Build stage
FROM golang:1.26.1-alpine AS builder

WORKDIR /app

# Enable automatic toolchain download if needed
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /parachute ./cmd/parachute

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

RUN addgroup -g 1000 parachute && \
    adduser -u 1000 -G parachute -s /bin/sh -D parachute

WORKDIR /app

COPY --from=builder /parachute /app/parachute

RUN mkdir -p /etc/parachute && chown parachute:parachute /etc/parachute
RUN mkdir -p /var/lib/parachute && chown parachute:parachute /var/lib/parachute

USER parachute

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/parachute"]
CMD ["--config", "/etc/parachute/config.yaml"]
