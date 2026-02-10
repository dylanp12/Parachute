FROM golang:1.25.0-alpine AS builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /echo-server main.go

FROM alpine:3.19
COPY --from=builder /echo-server /echo-server
EXPOSE 8080
ENTRYPOINT ["/echo-server"]
