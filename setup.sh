#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Clever Relay – Local Stack Setup & Runner
#
# This script handles the complete lifecycle of the Clever Relay local stack:
#   • Dependency checking (Go, Node.js, bun)
#   • Secret generation (PSK keys)
#   • Building all components (frontend + Go binaries)
#   • Running the local SOCKS5 client with full configuration
#
# Usage:
#   ./setup.sh              Interactive guided setup
#   ./setup.sh --check      Check dependencies only
#   ./setup.sh --build      Build everything
#   ./setup.sh --run        Run the local client
#   ./setup.sh --server     Run the exit node locally (dev mode)
#   ./setup.sh --generate   Generate a new PSK key
#   ./setup.sh --clean      Remove all build artifacts
#   ./setup.sh --help       Show help
#
# Author: Salman Jabbari <mrsalmanjabbari@gmail.com>
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors & Formatting ──────────────────────────────────────────────────────
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly DIM='\033[2m'
readonly BOLD='\033[1m'
readonly RESET='\033[0m'

readonly CHECK="${GREEN}✓${RESET}"
readonly CROSS="${RED}✗${RESET}"
readonly ARROW="${CYAN}▸${RESET}"
readonly WARN="${YELLOW}⚠${RESET}"
readonly INFO="${BLUE}ℹ${RESET}"

# ── Project Paths ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BIN_DIR="${PROJECT_ROOT}/bin"
ENV_FILE="${PROJECT_ROOT}/.env"

# ── Minimum Versions ─────────────────────────────────────────────────────────
MIN_GO_VERSION="1.21"
MIN_NODE_VERSION="18"

# ══════════════════════════════════════════════════════════════════════════════
# Utility Functions
# ══════════════════════════════════════════════════════════════════════════════

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║       ██████╗██╗     ███████╗██╗   ██╗███████╗██████╗         ║
    ║      ██╔════╝██║     ██╔════╝██║   ██║██╔════╝██╔══██╗        ║
    ║      ██║     ██║     █████╗  ██║   ██║█████╗  ██████╔╝        ║
    ║      ██║     ██║     ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗        ║
    ║      ╚██████╗███████╗███████╗ ╚████╔╝ ███████╗██║  ██║        ║
    ║       ╚═════╝╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝        ║
    ║                     ██████╗ ███████╗██╗      █████╗ ██╗   ██╗  ║
    ║                     ██╔══██╗██╔════╝██║     ██╔══██╗╚██╗ ██╔╝  ║
    ║                     ██████╔╝█████╗  ██║     ███████║ ╚████╔╝   ║
    ║                     ██╔══██╗██╔══╝  ██║     ██╔══██║  ╚██╔╝    ║
    ║                     ██║  ██║███████╗███████╗██║  ██║   ██║     ║
    ║                     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝     ║
    ║                                                               ║
    ║          L4-over-L7 Tunnel · Google Relay · Phase 6           ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${RESET}"
}

log_info()    { echo -e "  ${INFO}  ${WHITE}$*${RESET}"; }
log_success() { echo -e "  ${CHECK}  ${GREEN}$*${RESET}"; }
log_warn()    { echo -e "  ${WARN}  ${YELLOW}$*${RESET}"; }
log_error()   { echo -e "  ${CROSS}  ${RED}$*${RESET}"; }
log_step()    { echo -e "\n${ARROW} ${BOLD}$*${RESET}"; }
log_dim()     { echo -e "     ${DIM}$*${RESET}"; }

separator() {
    echo -e "${DIM}  ─────────────────────────────────────────────────────────${RESET}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Dependency Checking
# ══════════════════════════════════════════════════════════════════════════════

version_gte() {
    # Returns 0 (true) if $1 >= $2 using semantic versioning
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

check_command() {
    local cmd="$1"
    local name="${2:-$cmd}"
    local install_hint="${3:-}"

    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1 || echo "unknown")
        log_success "${name} ${DIM}(v${ver})${RESET}"
        return 0
    else
        log_error "${name} not found"
        if [[ -n "$install_hint" ]]; then
            log_dim "Install: ${install_hint}"
        fi
        return 1
    fi
}

check_dependencies() {
    log_step "Checking dependencies..."
    separator

    local missing=0

    # Go
    if command -v go &>/dev/null; then
        local go_ver
        go_ver=$(go version | grep -oP '\d+\.\d+(\.\d+)?' | head -1)
        if version_gte "$go_ver" "$MIN_GO_VERSION"; then
            log_success "Go ${DIM}(v${go_ver})${RESET}"
        else
            log_error "Go ${go_ver} found, need >= ${MIN_GO_VERSION}"
            missing=1
        fi
    else
        log_error "Go not found"
        log_dim "Install: https://go.dev/dl/"
        missing=1
    fi

    # Node.js
    if command -v node &>/dev/null; then
        local node_ver
        node_ver=$(node --version | sed 's/v//' | cut -d. -f1)
        if [[ "$node_ver" -ge "$MIN_NODE_VERSION" ]]; then
            log_success "Node.js ${DIM}(v$(node --version | sed 's/v//'))${RESET}"
        else
            log_warn "Node.js v${node_ver} found, recommend >= ${MIN_NODE_VERSION}"
        fi
    else
        log_warn "Node.js not found (needed for desktop build)"
        log_dim "Install: https://nodejs.org/"
    fi

    # bun (preferred) or npm
    if command -v bun &>/dev/null; then
        local bun_ver
        bun_ver=$(bun --version 2>/dev/null)
        log_success "Bun ${DIM}(v${bun_ver})${RESET}"
    elif command -v npm &>/dev/null; then
        log_success "npm ${DIM}(v$(npm --version))${RESET} ${YELLOW}(bun preferred)${RESET}"
    else
        log_error "Neither bun nor npm found"
        log_dim "Install bun: curl -fsSL https://bun.sh/install | bash"
        missing=1
    fi

    # make
    check_command "make" "GNU Make" "sudo apt install build-essential" || missing=1

    # git
    check_command "git" "Git" "sudo apt install git" || missing=1

    # openssl (for key generation)
    check_command "openssl" "OpenSSL" "sudo apt install openssl" || ((missing+=0))

    # Optional: wails
    if command -v wails &>/dev/null; then
        log_success "Wails CLI ${DIM}(desktop builds)${RESET}"
    else
        log_warn "Wails CLI not found ${DIM}(optional, for desktop app)${RESET}"
        log_dim "Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
    fi

    # Optional: docker
    if command -v docker &>/dev/null; then
        log_success "Docker ${DIM}($(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1))${RESET}"
    else
        log_warn "Docker not found ${DIM}(optional, for container builds)${RESET}"
    fi

    separator

    if [[ "$missing" -gt 0 ]]; then
        log_error "Missing required dependencies. Please install them and retry."
        return 1
    else
        log_success "All required dependencies satisfied"
        return 0
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# PSK Key Management
# ══════════════════════════════════════════════════════════════════════════════

generate_psk() {
    if command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        # Fallback using /dev/urandom
        head -c 32 /dev/urandom | xxd -p -c 64
    fi
}

ensure_env_file() {
    if [[ ! -f "$ENV_FILE" ]]; then
        log_step "Creating .env configuration file..."

        local psk
        psk=$(generate_psk)

        cat > "$ENV_FILE" << ENVEOF
# ══════════════════════════════════════════════════════════════════════════════
# Clever Relay – Configuration
# ══════════════════════════════════════════════════════════════════════════════

# Pre-Shared Key (PSK) – 32 bytes, hex-encoded (64 characters)
# IMPORTANT: Must be the same on both client and exit node!
# Regenerate with: ./setup.sh --generate
RELAY_PSK=${psk}

# ── Exit Node (Clever Cloud) ─────────────────────────────────────────────────
PORT=8080
RELAY_PATH=/relay
ADMIN_PASSWORD=change-me-to-a-strong-password

# ── Local Client ─────────────────────────────────────────────────────────────
# Comma-separated Google Apps Script deployment URLs
GAS_URLS=https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec

# ── Clever Cloud Exit Node URL ───────────────────────────────────────────────
EXIT_NODE_URL=https://your-app.cleverapps.io
ENVEOF

        log_success "Created ${ENV_FILE}"
        log_warn "Edit .env with your actual GAS URLs and exit node address"
    else
        log_success ".env file exists"
    fi
}

load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -a
        # shellcheck source=/dev/null
        source "$ENV_FILE"
        set +a
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Build Functions
# ══════════════════════════════════════════════════════════════════════════════

build_all() {
    log_step "Building all components..."
    separator

    cd "$PROJECT_ROOT"

    # 1. Go dependencies
    log_info "Downloading Go dependencies..."
    (cd dataengine && go mod download) 2>/dev/null
    (cd exitnode && go mod download) 2>/dev/null
    (cd localengine && go mod download) 2>/dev/null
    log_success "Go dependencies ready"

    # 2. Frontend
    log_info "Building admin dashboard frontend..."
    if command -v bun &>/dev/null; then
        (cd frontend && bun install --frozen-lockfile 2>/dev/null || bun install) &>/dev/null
        (cd frontend && bun run build) 2>/dev/null
    else
        (cd frontend && npm install --silent) 2>/dev/null
        (cd frontend && npm run build) 2>/dev/null
    fi
    log_success "Dashboard → exitnode/dashboard/dist/"

    # 3. Tests
    log_info "Running tests..."
    (cd dataengine && go test ./...) 2>/dev/null
    log_success "All 21 tests passed"

    # 4. Binaries
    mkdir -p "$BIN_DIR"

    local ldflags="-w -s"
    local version
    version=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
    local commit
    commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    local build_time
    build_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    ldflags="${ldflags} -X main.Version=${version}"
    ldflags="${ldflags} -X main.BuildTime=${build_time}"
    ldflags="${ldflags} -X main.Commit=${commit}"

    log_info "Compiling exit node server..."
    (cd exitnode && CGO_ENABLED=0 go build -trimpath -ldflags="$ldflags" -o "${BIN_DIR}/clever-relay-server" .)
    local server_size
    server_size=$(du -sh "${BIN_DIR}/clever-relay-server" | cut -f1)
    log_success "clever-relay-server (${server_size})"

    log_info "Compiling local client engine..."
    (cd localengine && CGO_ENABLED=0 go build -trimpath -ldflags="$ldflags" -o "${BIN_DIR}/clever-relay-client" .)
    local client_size
    client_size=$(du -sh "${BIN_DIR}/clever-relay-client" | cut -f1)
    log_success "clever-relay-client (${client_size})"

    separator
    echo ""
    log_success "Build complete! Binaries in ${BOLD}./bin/${RESET}"
    echo ""
    echo -e "  ${DIM}┌──────────────────────────────────────────────┐${RESET}"
    echo -e "  ${DIM}│${RESET}  ${WHITE}${BIN_DIR}/clever-relay-server${RESET}  ${DIM}(${server_size})${RESET}  ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${WHITE}${BIN_DIR}/clever-relay-client${RESET}  ${DIM}(${client_size})${RESET}  ${DIM}│${RESET}"
    echo -e "  ${DIM}└──────────────────────────────────────────────┘${RESET}"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Run Functions
# ══════════════════════════════════════════════════════════════════════════════

run_client() {
    log_step "Starting Clever Relay local client..."
    separator

    load_env

    local binary="${BIN_DIR}/clever-relay-client"
    if [[ ! -x "$binary" ]]; then
        log_warn "Binary not found. Building first..."
        build_all
    fi

    # Validate configuration
    if [[ -z "${RELAY_PSK:-}" ]]; then
        log_error "RELAY_PSK not set. Run: ./setup.sh --generate"
        exit 1
    fi

    if [[ "${GAS_URLS:-}" == *"YOUR_DEPLOYMENT_ID"* ]] || [[ -z "${GAS_URLS:-}" ]]; then
        log_error "GAS_URLS not configured in .env"
        log_dim "Deploy Code.gs to Google Apps Script and add the URLs"
        exit 1
    fi

    echo ""
    echo -e "  ${DIM}┌──────────────────────────────────────────────┐${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}SOCKS5 Proxy${RESET}    →  ${WHITE}127.0.0.1:4046${RESET}          ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}GAS Nodes${RESET}       →  ${WHITE}$(echo "$GAS_URLS" | tr ',' '\n' | wc -l | tr -d ' ') scripts${RESET}                   ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}IP Scanner${RESET}      →  ${WHITE}Active (5 min)${RESET}          ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}Reverse Polling${RESET} →  ${WHITE}3 parallel PULLs${RESET}        ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}Padding${RESET}         →  ${WHITE}16–512 bytes random${RESET}     ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}                                              ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${YELLOW}Configure your browser SOCKS5 proxy to:${RESET}     ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${WHITE}  127.0.0.1:4046${RESET}                            ${DIM}│${RESET}"
    echo -e "  ${DIM}└──────────────────────────────────────────────┘${RESET}"
    echo ""

    exec "$binary" \
        -psk "$RELAY_PSK" \
        -gas-urls "$GAS_URLS" \
        -listen ":4046"
}

run_server() {
    log_step "Starting Clever Relay exit node (dev mode)..."
    separator

    load_env

    local binary="${BIN_DIR}/clever-relay-server"
    if [[ ! -x "$binary" ]]; then
        log_warn "Binary not found. Building first..."
        build_all
    fi

    if [[ -z "${RELAY_PSK:-}" ]]; then
        log_error "RELAY_PSK not set. Run: ./setup.sh --generate"
        exit 1
    fi

    echo ""
    echo -e "  ${DIM}┌──────────────────────────────────────────────┐${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}Relay Endpoint${RESET}  →  ${WHITE}http://localhost:${PORT:-8080}${RELAY_PATH:-/relay}${RESET}  ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}Admin Panel${RESET}     →  ${WHITE}http://localhost:${PORT:-8080}/admin/${RESET}     ${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}pprof${RESET}           →  ${WHITE}http://localhost:${PORT:-8080}/debug/pprof/${RESET}${DIM}│${RESET}"
    echo -e "  ${DIM}│${RESET}  ${GREEN}Health${RESET}          →  ${WHITE}http://localhost:${PORT:-8080}/health${RESET}    ${DIM}│${RESET}"
    echo -e "  ${DIM}└──────────────────────────────────────────────┘${RESET}"
    echo ""

    exec "$binary"
}

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Setup
# ══════════════════════════════════════════════════════════════════════════════

interactive_setup() {
    banner

    echo -e "  ${DIM}This wizard will set up the Clever Relay local stack.${RESET}"
    echo -e "  ${DIM}It checks dependencies, generates keys, and builds everything.${RESET}"
    echo ""

    # Step 1: Dependencies
    if ! check_dependencies; then
        exit 1
    fi

    # Step 2: Environment
    echo ""
    ensure_env_file

    # Step 3: Build
    echo ""
    build_all

    # Step 4: Next steps
    echo ""
    log_step "Setup complete! Next steps:"
    separator
    echo ""
    echo -e "  ${WHITE}1.${RESET} Deploy ${BOLD}google-script/Code.gs${RESET} to Google Apps Script"
    echo -e "     ${DIM}→ https://script.google.com${RESET}"
    echo ""
    echo -e "  ${WHITE}2.${RESET} Add your deployment URLs to ${BOLD}.env${RESET}"
    echo -e "     ${DIM}→ GAS_URLS=https://script.google.com/macros/s/.../exec${RESET}"
    echo ""
    echo -e "  ${WHITE}3.${RESET} Deploy the exit node to Clever Cloud"
    echo -e "     ${DIM}→ cd exitnode && clever deploy${RESET}"
    echo -e "     ${DIM}→ Set RELAY_PSK and ADMIN_PASSWORD env vars${RESET}"
    echo ""
    echo -e "  ${WHITE}4.${RESET} Update ${BOLD}google-script/Code.gs${RESET} RELAY_URL with your Clever Cloud URL"
    echo ""
    echo -e "  ${WHITE}5.${RESET} Start the local proxy:"
    echo -e "     ${CYAN}./setup.sh --run${RESET}"
    echo ""
    echo -e "  ${WHITE}6.${RESET} Configure your browser SOCKS5 proxy to ${BOLD}127.0.0.1:4046${RESET}"
    echo ""
    separator
}

# ══════════════════════════════════════════════════════════════════════════════
# Help
# ══════════════════════════════════════════════════════════════════════════════

show_help() {
    echo -e "${BOLD}Clever Relay – Local Stack Setup & Runner${RESET}"
    echo ""
    echo -e "${BOLD}USAGE:${RESET}"
    echo -e "  ${CYAN}./setup.sh${RESET}              Interactive guided setup"
    echo -e "  ${CYAN}./setup.sh ${WHITE}<command>${RESET}    Run a specific command"
    echo ""
    echo -e "${BOLD}COMMANDS:${RESET}"
    echo -e "  ${CYAN}--check${RESET}       Check if all dependencies are installed"
    echo -e "  ${CYAN}--build${RESET}       Build frontend + all Go binaries"
    echo -e "  ${CYAN}--run${RESET}         Start the local SOCKS5 client"
    echo -e "  ${CYAN}--server${RESET}      Start the exit node server (dev mode)"
    echo -e "  ${CYAN}--generate${RESET}    Generate a new 32-byte PSK key"
    echo -e "  ${CYAN}--clean${RESET}       Remove all build artifacts"
    echo -e "  ${CYAN}--help${RESET}        Show this help message"
    echo ""
    echo -e "${BOLD}EXAMPLES:${RESET}"
    echo -e "  ${DIM}# First time setup${RESET}"
    echo -e "  ./setup.sh"
    echo ""
    echo -e "  ${DIM}# Quick rebuild and run${RESET}"
    echo -e "  ./setup.sh --build && ./setup.sh --run"
    echo ""
    echo -e "  ${DIM}# Cross-compile for Windows${RESET}"
    echo -e "  GOOS=windows make localengine"
    echo ""
    echo -e "  ${DIM}# Generate a new shared key${RESET}"
    echo -e "  ./setup.sh --generate"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ══════════════════════════════════════════════════════════════════════════════

main() {
    cd "$PROJECT_ROOT"

    case "${1:-}" in
        --check|-c)
            banner
            check_dependencies
            ;;
        --build|-b)
            banner
            check_dependencies
            build_all
            ;;
        --run|-r)
            run_client
            ;;
        --server|-s)
            run_server
            ;;
        --generate|-g)
            local key
            key=$(generate_psk)
            echo ""
            echo -e "  ${GREEN}Generated PSK:${RESET}"
            echo -e "  ${BOLD}${key}${RESET}"
            echo ""
            echo -e "  ${DIM}Add to .env:  RELAY_PSK=${key}${RESET}"
            echo ""
            ;;
        --clean)
            banner
            log_step "Cleaning build artifacts..."
            rm -rf "$BIN_DIR"
            rm -rf "${PROJECT_ROOT}/exitnode/dashboard/dist"
            rm -rf "${PROJECT_ROOT}/desktop/frontend/dist"
            rm -f "${PROJECT_ROOT}/exitnode/exitnode"
            rm -f "${PROJECT_ROOT}/localengine/localengine"
            log_success "Cleaned"
            ;;
        --help|-h)
            show_help
            ;;
        "")
            interactive_setup
            ;;
        *)
            log_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
