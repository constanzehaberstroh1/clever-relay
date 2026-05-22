# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Build Frontend
# ──────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app
# کپی کامل پروژه برای دسترسی به ساختار sibling پوشه‌ها
COPY . . 
WORKDIR /app/frontend
RUN npm install && npm run build

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Build Go Binary
# ──────────────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# کپی سورس کدها
COPY dataengine/ ./dataengine/
COPY exitnode/ ./exitnode/

# کپی فایل‌های بیلد شده از خروجی Vite (طبق لاگ شما)
# از استیج اول به مسیر مطلق در استیج دوم
COPY --from=frontend-builder /app/exitnode/dashboard/dist/ /build/exitnode/dashboard/dist/

# بیلد کردن Go
WORKDIR /build/exitnode
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -trimpath \
    -o /build/exitnode-bin .

# ──────────────────────────────────────────────────────────────────────────────
# Stage 3: Runtime
# ──────────────────────────────────────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user
RUN adduser -D -u 1000 relay
USER relay

WORKDIR /app
COPY --from=builder /build/exitnode-bin /app/exitnode

EXPOSE 8080
ENV PORT=8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/exitnode"]