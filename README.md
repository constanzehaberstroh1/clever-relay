<div align="center">

# Clever Relay

**L4-over-L7 Tunnel · Google Relay · Enterprise Stealth VPN**

A high-performance, enterprise-grade tunneling system that routes traffic through Google Apps Script relays to a dedicated exit node on Clever Cloud, providing a stable, unrestricted internet connection with a clean European IP address.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![License](https://img.shields.io/badge/License-Private-red?style=flat)](#)

</div>

---

## Architecture

```
┌──────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌──────────┐
│  Browser │────▶│  Local Client   │────▶│  Google Apps     │────▶│  Exit    │────▶ Internet
│  SOCKS5  │     │  (Go, :1080)    │     │  Script Relay    │     │  Node    │     (YouTube,
│          │◀────│  ChaCha20+Zstd  │◀────│  (fetchAll)      │◀────│  (CC)    │◀──── ChatGPT)
└──────────┘     └─────────────────┘     └─────────────────┘     └──────────┘
                  H2 Multiplexing         Dumb Pipe (Base64)      Port 8080
                  SNI Rotation            Status Forwarding       TCP/UDP Proxy
                  Clean IP Routing        Quota Tracking          Time-Aware Preemption
```

## Features

| Layer | Feature | Description |
|-------|---------|-------------|
| 🔐 **Crypto** | ChaCha20-Poly1305 | AEAD encryption with Silent Drop anti-probing |
| 📦 **Compression** | Zstd (SpeedFastest) | 2-3x compression before encryption |
| 🎭 **Stealth** | Random Padding | 16–512 byte noise defeats AI-based DPI |
| 🌐 **Transport** | H2 + SNI Rotation | Multiplexed connections via whitelisted Google domains |
| 🔍 **Routing** | Clean IP Scanner | Background probe → route through fastest Google IPs |
| ⚡ **Performance** | Reverse Polling | 3 concurrent pending PULLs for minimal latency |
| ♻️ **Memory** | sync.Pool | Recycled buffers eliminate GC pressure during 4K streaming |
| 📊 **Monitoring** | Real-time Dashboard | WebSocket metrics, session viewer, async ring-buffered logs |

## Quick Start

```bash
# Clone and setup
git clone https://github.com/constanzehaberstroh1/clever-relay.git
cd clever-relay

# Interactive setup (checks deps, generates keys, builds everything)
./setup.sh

# Or build manually
make

# Run the local SOCKS5 proxy
./setup.sh --run
```

## Project Structure

```
clever-relay/
├── dataengine/          # Shared protocol: binary serialization + ChaCha20 + Zstd
│   ├── packet.go        # TunnelPacket struct, command constants, sync.Pool
│   ├── crypto.go        # ChaCha20-Poly1305 AEAD + Silent Drop
│   ├── compress.go      # Zstd encoder/decoder (SpeedFastest)
│   ├── padding.go       # Random padding for DPI traffic obfuscation
│   └── protocol.go      # Seal/Open pipeline (serialize → compress → encrypt → pad)
│
├── exitnode/             # Clever Cloud exit node server
│   ├── main.go          # HTTP server (:8080) + pprof
│   ├── relay.go         # POST /relay handler, TCP/UDP session dispatch
│   ├── session.go       # SessionStore (sync.Map) + reaper
│   ├── admin.go         # JWT auth, WebSocket streaming, embedded SPA
│   ├── logger.go        # Ring-buffered async logging (5000 entries)
│   ├── metrics.go       # CPU/RAM/goroutine monitoring from /proc
│   └── Dockerfile       # Multi-stage Go → Alpine for Clever Cloud
│
├── google-script/       # Google Apps Script relay
│   └── Code.gs          # doPost (single) + doBatchPost (fetchAll parallel)
│
├── localengine/         # Local SOCKS5 client engine
│   ├── main.go          # CLI entrypoint with flags + env vars
│   ├── socks5.go        # SOCKS5 server + Reverse Polling downlink
│   ├── chunker.go       # Micro-batching (10ms / 256KB flush)
│   ├── pool.go          # Weighted least-latency GAS pool + Circuit Breaker
│   ├── transport.go     # H2 multiplexing + SNI rotation + Clean IP routing
│   ├── downlink.go      # Min-Heap sequence reassembly
│   └── scanner.go       # Background Google IP range scanner
│
├── frontend/            # Admin dashboard (React + Vite → embedded in exitnode)
├── desktop/             # Wails desktop app (Go + React + SQLite)
│
├── Makefile             # Build system (make, make test, make release, make docker)
├── setup.sh             # Interactive setup & run script
├── .env                 # Configuration (PSK, GAS URLs, admin password)
└── .gitignore
```

## Configuration

Copy and edit the environment file:

```bash
# Generate a fresh PSK
./setup.sh --generate

# Edit .env with your values
vim .env
```

| Variable | Description | Example |
|----------|-------------|---------|
| `RELAY_PSK` | 32-byte hex key (shared secret) | `openssl rand -hex 32` |
| `GAS_URLS` | Comma-separated GAS deployment URLs | `https://script.google.com/macros/s/.../exec` |
| `PORT` | Exit node listen port | `8080` |
| `ADMIN_PASSWORD` | Dashboard login password | `your-strong-password` |

## Build Commands

```bash
make                          # Build frontend + all binaries → ./bin/
make exitnode                 # Build only the exit node server
make localengine              # Build only the SOCKS5 client
make desktop                  # Build Wails desktop app (requires wails CLI)
make test                     # Run all 21 tests with race detector
make lint                     # go vet across all modules
make release                  # Cross-compile for Linux/macOS/Windows (amd64+arm64)
make docker                   # Build Docker image for Clever Cloud
make GOOS=windows localengine # Cross-compile client for Windows
make clean                    # Remove all build artifacts
```

## Deployment

### Exit Node (Clever Cloud)

```bash
# Set environment variables in Clever Cloud console:
#   RELAY_PSK=<your-64-hex-char-key>
#   ADMIN_PASSWORD=<your-dashboard-password>

# Deploy via Docker
cd exitnode
clever deploy
```

### Google Apps Script

1. Go to [script.google.com](https://script.google.com)
2. Create a new project
3. Paste `google-script/Code.gs`
4. Update `RELAY_URL` to your Clever Cloud app URL
5. Deploy as Web App (Execute as: Me, Access: Anyone)
6. Copy the deployment URL to `.env` → `GAS_URLS`

### Local Client

```bash
# Configure and run
./setup.sh --run

# Or manually
./bin/clever-relay-client \
  -psk "$RELAY_PSK" \
  -gas-urls "$GAS_URLS" \
  -listen ":1080"
```

## Protocol

```
Wire format (24-byte header):
┌─────────┬─────────┬──────────────────┬──────────┬───────────┬────────┬─────────┐
│ Version │ Command │    SessionID     │  SeqNum  │ TargetLen │ Target │ Payload │
│  1 byte │  1 byte │    16 bytes      │ 4 bytes  │  2 bytes  │ N bytes│ M bytes │
└─────────┴─────────┴──────────────────┴──────────┴───────────┴────────┴─────────┘

Pipeline: Serialize → Zstd Compress → ChaCha20-Poly1305 Encrypt → Random Pad
```

## License

Private repository. All rights reserved.
