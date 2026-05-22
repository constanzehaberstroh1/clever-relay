#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Clever Relay – Local Stack Runner
#
# Starts the full local development stack with interactive controls.
#
# Usage:
#   ./start.sh                  Start full local stack (server + client)
#   ./start.sh --client         Start only the SOCKS5 client
#   ./start.sh --server         Start only the exit node server
#   ./start.sh --desktop        Start the Wails desktop app
#   ./start.sh --status         Show running component status
#   ./start.sh --stop           Stop all running components
#   ./start.sh --help           Show help
#
# Interactive Keys (while running):
#   [d] Open admin dashboard in browser
#   [w] Launch Wails desktop app
#   [s] Show status of all components
#   [l] Tail server logs
#   [r] Restart all components
#   [q] Graceful shutdown
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
ENV_FILE="${SCRIPT_DIR}/.env"
PID_DIR="${SCRIPT_DIR}/.run"
LOG_DIR="${SCRIPT_DIR}/.run/logs"

SERVER_BIN="${BIN_DIR}/clever-relay-server"
CLIENT_BIN="${BIN_DIR}/clever-relay-client"
SERVER_PID="${PID_DIR}/server.pid"
CLIENT_PID="${PID_DIR}/client.pid"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

# ── Colors ────────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[2m'; BD='\033[1m'; RST='\033[0m'

OK="${G}✓${RST}"; FAIL="${R}✗${RST}"; WARN="${Y}⚠${RST}"; DOT="${C}▸${RST}"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "  ${DOT} ${W}$*${RST}"; }
ok()      { echo -e "  ${OK} ${G}$*${RST}"; }
warn()    { echo -e "  ${WARN} ${Y}$*${RST}"; }
err()     { echo -e "  ${FAIL} ${R}$*${RST}"; }
dim()     { echo -e "     ${D}$*${RST}"; }
sep()     { echo -e "  ${D}─────────────────────────────────────────────────────${RST}"; }

is_running() {
    local pidfile="$1"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null
}

kill_pid() {
    local pidfile="$1" name="$2"
    if is_running "$pidfile"; then
        local pid; pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$pidfile"
        ok "${name} stopped (PID ${pid})"
    fi
}

open_browser() {
    local url="$1"
    if command -v xdg-open &>/dev/null; then xdg-open "$url" 2>/dev/null &
    elif command -v open &>/dev/null; then open "$url" 2>/dev/null &
    elif command -v wslview &>/dev/null; then wslview "$url" 2>/dev/null &
    else warn "Cannot open browser. Visit: ${url}"; return; fi
    ok "Opened ${url}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════

banner() {
    echo -e "${C}${BD}"
    cat << 'BANNER'
     ┌─────────────────────────────────────────────────┐
     │        CLEVER RELAY · Local Stack Runner        │
     │          L4-over-L7 Tunnel · Phase 6            │
     └─────────────────────────────────────────────────┘
BANNER
    echo -e "${RST}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Environment
# ══════════════════════════════════════════════════════════════════════════════

load_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        err ".env file not found. Run ./setup.sh first."
        exit 1
    fi
    set -a; source "$ENV_FILE"; set +a
}

validate_env() {
    local fail=0
    if [[ -z "${RELAY_PSK:-}" ]]; then
        err "RELAY_PSK not set in .env"; fail=1
    elif [[ ${#RELAY_PSK} -ne 64 ]]; then
        err "RELAY_PSK must be 64 hex chars (got ${#RELAY_PSK})"; fail=1
    fi
    if [[ -z "${ADMIN_PASSWORD:-}" ]] || [[ "${ADMIN_PASSWORD}" == "change-me"* ]]; then
        warn "ADMIN_PASSWORD not set or still default — dashboard disabled"
    fi
    return $fail
}

# ══════════════════════════════════════════════════════════════════════════════
# Build
# ══════════════════════════════════════════════════════════════════════════════

ensure_binaries() {
    local need_build=0
    [[ ! -x "$SERVER_BIN" ]] && need_build=1
    [[ ! -x "$CLIENT_BIN" ]] && need_build=1

    if [[ $need_build -eq 1 ]]; then
        info "Binaries not found — building..."
        make -C "$SCRIPT_DIR" all --no-print-directory 2>&1 | while IFS= read -r line; do
            dim "$line"
        done
        if [[ ! -x "$SERVER_BIN" ]] || [[ ! -x "$CLIENT_BIN" ]]; then
            err "Build failed. Run 'make' manually to see errors."
            exit 1
        fi
        ok "Build complete"
    else
        ok "Binaries ready"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Start Components
# ══════════════════════════════════════════════════════════════════════════════

start_server() {
    if is_running "$SERVER_PID"; then
        warn "Server already running (PID $(cat "$SERVER_PID"))"
        return 0
    fi

    info "Starting exit node server on :${PORT:-8080}..."

    RELAY_PSK="${RELAY_PSK}" \
    PORT="${PORT:-8080}" \
    RELAY_PATH="${RELAY_PATH:-/relay}" \
    ADMIN_PASSWORD="${ADMIN_PASSWORD:-}" \
    nohup "$SERVER_BIN" > "$SERVER_LOG" 2>&1 &

    echo $! > "$SERVER_PID"
    sleep 0.5

    if is_running "$SERVER_PID"; then
        ok "Exit node started (PID $(cat "$SERVER_PID"))"
        dim "Relay    → http://localhost:${PORT:-8080}${RELAY_PATH:-/relay}"
        dim "Health   → http://localhost:${PORT:-8080}/health"
        dim "Admin    → http://localhost:${PORT:-8080}/admin/"
        dim "pprof    → http://localhost:${PORT:-8080}/debug/pprof/"
        dim "Logs     → ${SERVER_LOG}"
    else
        err "Server failed to start. Check: ${SERVER_LOG}"
        [[ -f "$SERVER_LOG" ]] && tail -5 "$SERVER_LOG" | while IFS= read -r l; do dim "$l"; done
        return 1
    fi
}

start_client() {
    if is_running "$CLIENT_PID"; then
        warn "Client already running (PID $(cat "$CLIENT_PID"))"
        return 0
    fi

    local gas="${GAS_URLS:-}"
    if [[ -z "$gas" ]] || [[ "$gas" == *"YOUR_DEPLOYMENT_ID"* ]]; then
        err "GAS_URLS not configured in .env"
        dim "Deploy Code.gs and add the URLs to .env"
        return 1
    fi

    local node_count
    node_count=$(echo "$gas" | tr ',' '\n' | grep -c '.')

    info "Starting SOCKS5 client on :1080..."

    RELAY_PSK="${RELAY_PSK}" \
    GAS_URLS="${gas}" \
    nohup "$CLIENT_BIN" -listen ":1080" -psk "$RELAY_PSK" -gas-urls "$gas" > "$CLIENT_LOG" 2>&1 &

    echo $! > "$CLIENT_PID"
    sleep 0.5

    if is_running "$CLIENT_PID"; then
        ok "SOCKS5 client started (PID $(cat "$CLIENT_PID"))"
        dim "Proxy    → 127.0.0.1:1080  (SOCKS5)"
        dim "Scripts  → ${node_count} GAS nodes"
        dim "Polling  → 3 parallel PULLs"
        dim "Padding  → 16–512 bytes random"
        dim "Logs     → ${CLIENT_LOG}"
    else
        err "Client failed to start. Check: ${CLIENT_LOG}"
        [[ -f "$CLIENT_LOG" ]] && tail -5 "$CLIENT_LOG" | while IFS= read -r l; do dim "$l"; done
        return 1
    fi
}

launch_desktop() {
    if ! command -v wails &>/dev/null; then
        err "Wails CLI not installed"
        dim "Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        return 1
    fi
    info "Launching Wails desktop app..."
    (cd "${SCRIPT_DIR}/desktop" && wails dev) &
    ok "Desktop app launching in background"
}

# ══════════════════════════════════════════════════════════════════════════════
# Status
# ══════════════════════════════════════════════════════════════════════════════

show_status() {
    echo ""
    echo -e "  ${BD}${W}Component Status${RST}"
    sep

    # Server
    if is_running "$SERVER_PID"; then
        local spid; spid=$(cat "$SERVER_PID")
        local smem; smem=$(ps -o rss= -p "$spid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        local sup; sup=$(ps -o etime= -p "$spid" 2>/dev/null | xargs)
        echo -e "  ${G}●${RST}  ${W}Exit Node Server${RST}   PID ${D}${spid}${RST}  RAM ${D}${smem}${RST}  Up ${D}${sup}${RST}"
        dim "   http://localhost:${PORT:-8080}/admin/"
    else
        echo -e "  ${R}○${RST}  ${D}Exit Node Server    stopped${RST}"
    fi

    # Client
    if is_running "$CLIENT_PID"; then
        local cpid; cpid=$(cat "$CLIENT_PID")
        local cmem; cmem=$(ps -o rss= -p "$cpid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        local cup; cup=$(ps -o etime= -p "$cpid" 2>/dev/null | xargs)
        echo -e "  ${G}●${RST}  ${W}SOCKS5 Client${RST}      PID ${D}${cpid}${RST}  RAM ${D}${cmem}${RST}  Up ${D}${cup}${RST}"
        dim "   socks5://127.0.0.1:1080"
    else
        echo -e "  ${R}○${RST}  ${D}SOCKS5 Client       stopped${RST}"
    fi

    sep
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Stop All
# ══════════════════════════════════════════════════════════════════════════════

stop_all() {
    echo ""
    info "Stopping all components..."
    kill_pid "$CLIENT_PID" "SOCKS5 Client"
    kill_pid "$SERVER_PID" "Exit Node Server"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Control Loop
# ══════════════════════════════════════════════════════════════════════════════

show_controls() {
    echo ""
    echo -e "  ${BD}${W}Interactive Controls${RST}"
    sep
    echo -e "  ${C}[d]${RST} Open admin dashboard     ${C}[w]${RST} Launch desktop app"
    echo -e "  ${C}[s]${RST} Show status              ${C}[l]${RST} Tail server logs"
    echo -e "  ${C}[r]${RST} Restart all              ${C}[c]${RST} Tail client logs"
    echo -e "  ${C}[p]${RST} Test proxy (curl)        ${C}[h]${RST} Health check"
    echo -e "  ${C}[q]${RST} Shutdown & exit"
    sep
    echo ""
}

interactive_loop() {
    show_controls

    while true; do
        echo -ne "  ${C}❯${RST} "
        # Read a single character without waiting for Enter
        if read -rsn1 -t 1 key 2>/dev/null; then
            echo ""
            case "$key" in
                d)
                    open_browser "http://localhost:${PORT:-8080}/admin/"
                    ;;
                w)
                    launch_desktop
                    ;;
                s)
                    show_status
                    ;;
                l)
                    if [[ -f "$SERVER_LOG" ]]; then
                        info "Server log (Ctrl+C to stop):"
                        tail -f "$SERVER_LOG" 2>/dev/null || true
                    else
                        warn "No server log file"
                    fi
                    ;;
                c)
                    if [[ -f "$CLIENT_LOG" ]]; then
                        info "Client log (Ctrl+C to stop):"
                        tail -f "$CLIENT_LOG" 2>/dev/null || true
                    else
                        warn "No client log file"
                    fi
                    ;;
                r)
                    info "Restarting..."
                    stop_all
                    start_server
                    start_client
                    show_status
                    ;;
                p)
                    info "Testing SOCKS5 proxy..."
                    if curl -s --connect-timeout 5 --socks5 127.0.0.1:1080 \
                        https://httpbin.org/ip 2>/dev/null; then
                        echo ""
                        ok "Proxy working!"
                    else
                        err "Proxy test failed — check client logs"
                    fi
                    ;;
                h)
                    info "Health check..."
                    local health
                    if health=$(curl -s --connect-timeout 3 \
                        "http://localhost:${PORT:-8080}/health" 2>/dev/null); then
                        ok "Server: ${health}"
                    else
                        err "Server not responding"
                    fi
                    ;;
                q)
                    echo ""
                    stop_all
                    ok "Goodbye."
                    echo ""
                    exit 0
                    ;;
                '?'|h)
                    show_controls
                    ;;
                *)
                    # Ignore unknown keys silently
                    ;;
            esac
        fi

        # Check if children are still alive
        if ! is_running "$SERVER_PID" && ! is_running "$CLIENT_PID"; then
            # Only warn if we had started them
            if [[ -f "$SERVER_PID" ]] || [[ -f "$CLIENT_PID" ]]; then
                echo ""
                err "All components have exited unexpectedly"
                warn "Check logs: ${LOG_DIR}/"
                exit 1
            fi
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Full Stack Start
# ══════════════════════════════════════════════════════════════════════════════

start_full_stack() {
    banner
    load_env

    echo -e "  ${BD}${W}Preflight Checks${RST}"
    sep

    if ! validate_env; then exit 1; fi
    ok "Environment validated"

    ensure_binaries

    mkdir -p "$PID_DIR" "$LOG_DIR"

    sep
    echo ""
    echo -e "  ${BD}${W}Starting Stack${RST}"
    sep

    start_server || exit 1
    echo ""

    # Only start client if GAS_URLS is configured
    local gas="${GAS_URLS:-}"
    if [[ -n "$gas" ]] && [[ "$gas" != *"YOUR_DEPLOYMENT_ID"* ]]; then
        start_client || true
    else
        warn "Skipping client — GAS_URLS not configured"
        dim "Server is running for direct testing"
    fi

    sep

    show_status

    echo -e "  ${BD}${G}Stack is running!${RST}"
    echo -e "  ${D}Configure browser SOCKS5 proxy → 127.0.0.1:1080${RST}"
    echo ""

    # Trap Ctrl+C for graceful shutdown
    trap 'echo ""; stop_all; ok "Goodbye."; echo ""; exit 0' INT TERM

    interactive_loop
}

# ══════════════════════════════════════════════════════════════════════════════
# Help
# ══════════════════════════════════════════════════════════════════════════════

show_help() {
    echo -e "${BD}Clever Relay – Local Stack Runner${RST}"
    echo ""
    echo -e "${BD}USAGE:${RST}"
    echo -e "  ${C}./start.sh${RST}              Start full stack with interactive controls"
    echo -e "  ${C}./start.sh ${W}<command>${RST}  Run a specific command"
    echo ""
    echo -e "${BD}COMMANDS:${RST}"
    echo -e "  ${C}--server${RST}      Start only the exit node server"
    echo -e "  ${C}--client${RST}      Start only the SOCKS5 client"
    echo -e "  ${C}--desktop${RST}     Launch the Wails desktop app"
    echo -e "  ${C}--dashboard${RST}   Open admin dashboard in browser"
    echo -e "  ${C}--status${RST}      Show running component status"
    echo -e "  ${C}--stop${RST}        Stop all running components"
    echo -e "  ${C}--logs${RST}        Tail both server and client logs"
    echo -e "  ${C}--help${RST}        Show this help"
    echo ""
    echo -e "${BD}INTERACTIVE KEYS:${RST}"
    echo -e "  ${C}d${RST}=dashboard  ${C}w${RST}=desktop  ${C}s${RST}=status  ${C}l${RST}=logs  ${C}r${RST}=restart  ${C}q${RST}=quit"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

main() {
    cd "$SCRIPT_DIR"

    case "${1:-}" in
        --server|-s)
            banner; load_env; validate_env || exit 1
            ensure_binaries; mkdir -p "$PID_DIR" "$LOG_DIR"
            start_server
            trap 'stop_all; exit 0' INT TERM
            info "Press Ctrl+C to stop"; tail -f "$SERVER_LOG"
            ;;
        --client|-c)
            banner; load_env; validate_env || exit 1
            ensure_binaries; mkdir -p "$PID_DIR" "$LOG_DIR"
            start_client
            trap 'stop_all; exit 0' INT TERM
            info "Press Ctrl+C to stop"; tail -f "$CLIENT_LOG"
            ;;
        --desktop|-w)
            banner; load_env; launch_desktop
            ;;
        --dashboard|-d)
            load_env; open_browser "http://localhost:${PORT:-8080}/admin/"
            ;;
        --status)
            banner; load_env; show_status
            ;;
        --stop)
            banner; stop_all
            ;;
        --logs)
            info "Tailing all logs (Ctrl+C to stop)..."
            tail -f "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null
            ;;
        --help|-h)
            show_help
            ;;
        "")
            start_full_stack
            ;;
        *)
            err "Unknown command: $1"; echo ""; show_help; exit 1
            ;;
    esac
}

main "$@"
