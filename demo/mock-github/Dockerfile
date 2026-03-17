FROM golang:1.25.0-alpine AS builder

WORKDIR /app
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /mock-github main.go

FROM alpine:3.19
COPY --from=builder /mock-github /mock-github
EXPOSE 9090
ENTRYPOINT ["/mock-github"]
