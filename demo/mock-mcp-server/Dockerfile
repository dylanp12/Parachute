FROM golang:1.25.0-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mock-mcp-server .

FROM alpine:3.19
COPY --from=builder /mock-mcp-server /mock-mcp-server
EXPOSE 3001
CMD ["/mock-mcp-server"]
