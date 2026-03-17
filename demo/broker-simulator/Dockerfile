FROM golang:1.25.0-alpine AS builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /broker-simulator main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /broker-simulator /broker-simulator
ENTRYPOINT ["/broker-simulator"]
