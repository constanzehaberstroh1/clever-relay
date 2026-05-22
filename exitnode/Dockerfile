# ──────────────────────────────────────────────────────────────────────────────
# Multi-stage Dockerfile for the Clever Relay Exit Node
# Optimized for minimal image size and fast startup on Clever Cloud
# ──────────────────────────────────────────────────────────────────────────────

# Stage 1: Build
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy the dataengine module first (dependency)
COPY dataengine/ ./dataengine/

# Copy the exitnode module
COPY exitnode/ ./exitnode/

# Download dependencies
WORKDIR /build/exitnode
RUN go mod download

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -trimpath \
    -o /build/exitnode-bin .

# Stage 2: Runtime
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user
RUN adduser -D -u 1000 relay
USER relay

WORKDIR /app

COPY --from=builder /build/exitnode-bin /app/exitnode

# Clever Cloud expects port 8080
EXPOSE 8080
ENV PORT=8080

# Health check for Clever Cloud
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/exitnode"]
