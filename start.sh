#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Clever Relay – Local Stack Runner
# ══════════════════════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"
ENV_FILE="${SCRIPT_DIR}/.env"
PID_DIR="${SCRIPT_DIR}/.run"
LOG_DIR="${SCRIPT_DIR}/.run/logs"

SERVER_BIN="${BIN_DIR}/clever-relay-server"
CLIENT_BIN="${BIN_DIR}/clever-relay-client"
SERVER_PID="${PID_DIR}/server.pid"
CLIENT_PID="${PID_DIR}/client.pid"
DESKTOP_PID="${PID_DIR}/desktop.pid"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"
DESKTOP_LOG="${LOG_DIR}/desktop.log"

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
    C='\033[0;36m'; W='\033[1;37m'; D='\033[2m'; BD='\033[1m'; RST='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; W=''; D=''; BD=''; RST=''
fi

OK="${G}✓${RST}"; FAIL="${R}✗${RST}"; WARN="${Y}⚠${RST}"; DOT="${C}▸${RST}"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { printf "  ${DOT} ${W}%s${RST}\n" "$*"; }
ok()    { printf "  ${OK} ${G}%s${RST}\n" "$*"; }
warn()  { printf "  ${WARN} ${Y}%s${RST}\n" "$*"; }
err()   { printf "  ${FAIL} ${R}%s${RST}\n" "$*"; }
dim()   { printf "     ${D}%s${RST}\n" "$*"; }
sep()   { printf "  ${D}─────────────────────────────────────────────────────${RST}\n"; }

is_running() {
    local pidfile="$1"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null
}

kill_pid() {
    local pidfile="$1" name="$2"
    if is_running "$pidfile"; then
        local pid
        pid=$(cat "$pidfile")
        kill "$pid" 2>/dev/null || true
        local i=0
        while kill -0 "$pid" 2>/dev/null && [[ $i -lt 30 ]]; do
            sleep 0.1
            i=$((i + 1))
        done
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$pidfile"
        ok "${name} stopped (PID ${pid})"
    else
        rm -f "$pidfile" 2>/dev/null || true
    fi
}

open_browser() {
    local url="$1"
    local opened=0
    # Try multiple browser openers
    if command -v xdg-open &>/dev/null; then
        nohup xdg-open "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        opened=1
    elif command -v open &>/dev/null; then
        open "$url" 2>/dev/null &
        disown 2>/dev/null || true
        opened=1
    elif command -v sensible-browser &>/dev/null; then
        nohup sensible-browser "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        opened=1
    elif command -v wslview &>/dev/null; then
        wslview "$url" 2>/dev/null &
        disown 2>/dev/null || true
        opened=1
    elif command -v firefox &>/dev/null; then
        nohup firefox "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        opened=1
    elif command -v google-chrome &>/dev/null; then
        nohup google-chrome "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        opened=1
    elif command -v chromium-browser &>/dev/null; then
        nohup chromium-browser "$url" >/dev/null 2>&1 &
        disown 2>/dev/null || true
        opened=1
    fi

    if [[ $opened -eq 1 ]]; then
        ok "Opened: ${url}"
    else
        warn "No browser found. Open manually:"
        dim "$url"
    fi
}

# ── Terminal helpers ──────────────────────────────────────────────────────────
save_term=""

setup_terminal() {
    if [[ -t 0 ]]; then
        save_term=$(stty -g 2>/dev/null || true)
    fi
}

restore_terminal() {
    if [[ -n "$save_term" ]] && [[ -t 0 ]]; then
        stty "$save_term" 2>/dev/null || true
    fi
    printf '\033[?25h' # ensure cursor is visible
}

# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════

banner() {
    printf "\n${C}${BD}"
    cat << 'BANNER'
     ┌─────────────────────────────────────────────────┐
     │        CLEVER RELAY · Local Stack Runner        │
     │          L4-over-L7 Tunnel · Phase 6            │
     └─────────────────────────────────────────────────┘
BANNER
    printf "${RST}\n"
}

# ══════════════════════════════════════════════════════════════════════════════
# Environment
# ══════════════════════════════════════════════════════════════════════════════

load_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        err ".env file not found. Run ./setup.sh first."
        exit 1
    fi
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
}

validate_env() {
    local fail=0
    if [[ -z "${RELAY_PSK:-}" ]]; then
        err "RELAY_PSK not set in .env"; fail=1
    elif [[ ${#RELAY_PSK} -ne 64 ]]; then
        err "RELAY_PSK must be 64 hex chars (got ${#RELAY_PSK})"; fail=1
    fi
    if [[ -z "${ADMIN_PASSWORD:-}" ]] || [[ "${ADMIN_PASSWORD}" == "change-me"* ]]; then
        warn "ADMIN_PASSWORD not set or still default"
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
        if make -C "$SCRIPT_DIR" all --no-print-directory 2>&1 | while IFS= read -r line; do
            dim "$line"
        done; then
            ok "Build complete"
        else
            err "Build failed. Run 'make' manually to see errors."
            exit 1
        fi
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
    sleep 0.8

    if is_running "$SERVER_PID"; then
        ok "Exit node started (PID $(cat "$SERVER_PID"))"
        dim "Relay    → http://localhost:${PORT:-8080}${RELAY_PATH:-/relay}"
        dim "Health   → http://localhost:${PORT:-8080}/health"
        dim "Admin    → http://localhost:${PORT:-8080}/admin/"
        dim "Logs     → ${SERVER_LOG}"
    else
        err "Server failed to start. Check: ${SERVER_LOG}"
        if [[ -f "$SERVER_LOG" ]]; then
            tail -5 "$SERVER_LOG" | while IFS= read -r l; do dim "$l"; done
        fi
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
    node_count=$(echo "$gas" | tr ',' '\n' | grep -c '.' || true)

    info "Starting SOCKS5 client on :1080..."

    RELAY_PSK="${RELAY_PSK}" \
    GAS_URLS="${gas}" \
    PANEL_ADDR="127.0.0.1:9090" \
    nohup "$CLIENT_BIN" -listen ":1080" -panel "127.0.0.1:9090" -psk "$RELAY_PSK" -gas-urls "$gas" > "$CLIENT_LOG" 2>&1 &

    echo $! > "$CLIENT_PID"
    sleep 0.5

    if is_running "$CLIENT_PID"; then
        ok "SOCKS5 client started (PID $(cat "$CLIENT_PID"))"
        dim "Proxy    → 127.0.0.1:1080  (SOCKS5)"
        dim "Panel    → http://127.0.0.1:9090"
        dim "Scripts  → ${node_count} GAS node(s)"
        dim "Logs     → ${CLIENT_LOG}"
    else
        err "Client failed to start. Check: ${CLIENT_LOG}"
        if [[ -f "$CLIENT_LOG" ]]; then
            tail -5 "$CLIENT_LOG" | while IFS= read -r l; do dim "$l"; done
        fi
        return 1
    fi
}

launch_desktop() {
    if is_running "$DESKTOP_PID"; then
        warn "Desktop already running (PID $(cat "$DESKTOP_PID"))"
        return 0
    fi

    if ! command -v wails &>/dev/null; then
        err "Wails CLI not installed"
        dim "Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest"
        return 0
    fi

    info "Launching Wails desktop app..."

    (cd "${SCRIPT_DIR}/desktop" && wails dev) > "$DESKTOP_LOG" 2>&1 &
    echo $! > "$DESKTOP_PID"
    disown 2>/dev/null || true
    sleep 1

    if is_running "$DESKTOP_PID"; then
        ok "Desktop app launched (PID $(cat "$DESKTOP_PID"))"
        dim "Logs → ${DESKTOP_LOG}"
    else
        err "Desktop app failed to start"
        if [[ -f "$DESKTOP_LOG" ]]; then
            tail -5 "$DESKTOP_LOG" | while IFS= read -r l; do dim "$l"; done
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Status
# ══════════════════════════════════════════════════════════════════════════════

show_status() {
    echo ""
    printf "  ${BD}${W}Component Status${RST}\n"
    sep

    local count=0

    # Server
    if is_running "$SERVER_PID"; then
        local spid smem sup
        spid=$(cat "$SERVER_PID")
        smem=$(ps -o rss= -p "$spid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || echo "?")
        sup=$(ps -o etime= -p "$spid" 2>/dev/null | xargs || echo "?")
        printf "  ${G}●${RST}  ${W}Exit Node Server${RST}   PID ${D}${spid}${RST}  RAM ${D}${smem}${RST}  Up ${D}${sup}${RST}\n"
        dim "   http://localhost:${PORT:-8080}/admin/"
        count=$((count + 1))
    else
        printf "  ${R}○${RST}  ${D}Exit Node Server    stopped${RST}\n"
    fi

    # Client
    if is_running "$CLIENT_PID"; then
        local cpid cmem cup
        cpid=$(cat "$CLIENT_PID")
        cmem=$(ps -o rss= -p "$cpid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || echo "?")
        cup=$(ps -o etime= -p "$cpid" 2>/dev/null | xargs || echo "?")
        printf "  ${G}●${RST}  ${W}SOCKS5 Client${RST}      PID ${D}${cpid}${RST}  RAM ${D}${cmem}${RST}  Up ${D}${cup}${RST}\n"
        dim "   socks5://127.0.0.1:1080"
        count=$((count + 1))
    else
        printf "  ${R}○${RST}  ${D}SOCKS5 Client       stopped${RST}\n"
    fi

    # Desktop
    if is_running "$DESKTOP_PID"; then
        local dpid
        dpid=$(cat "$DESKTOP_PID")
        printf "  ${G}●${RST}  ${W}Desktop App${RST}        PID ${D}${dpid}${RST}\n"
        count=$((count + 1))
    fi

    sep
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Stop
# ══════════════════════════════════════════════════════════════════════════════

stop_all() {
    echo ""
    info "Stopping all components..."
    kill_pid "$DESKTOP_PID" "Desktop App"
    kill_pid "$CLIENT_PID" "SOCKS5 Client"
    kill_pid "$SERVER_PID" "Exit Node Server"
    echo ""
}

stop_server() {
    kill_pid "$SERVER_PID" "Exit Node Server"
}

stop_client() {
    kill_pid "$CLIENT_PID" "SOCKS5 Client"
}

stop_desktop() {
    kill_pid "$DESKTOP_PID" "Desktop App"
}

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Control Loop
# ══════════════════════════════════════════════════════════════════════════════

show_controls() {
    echo ""
    printf "  ${BD}${W}Interactive Controls${RST}\n"
    sep
    printf "  ${C}d${RST} Server admin dashboard     ${C}a${RST} Client admin panel\n"
    printf "  ${C}w${RST} Launch desktop app         ${C}s${RST} Show status\n"
    printf "  ${C}l${RST} Tail server logs           ${C}c${RST} Tail client logs\n"
    printf "  ${C}r${RST} Restart all                ${C}p${RST} Test proxy (curl)\n"
    printf "  ${C}h${RST} Health check\n"
    sep
    printf "  ${Y}1${RST} Kill server                ${Y}2${RST} Kill client\n"
    printf "  ${Y}3${RST} Kill desktop               ${Y}0${RST} Kill ALL\n"
    sep
    printf "  ${C}q${RST} Shutdown & exit            ${C}?${RST} Show this help\n"
    sep
    echo ""
}

interactive_loop() {
    show_controls

    setup_terminal
    trap 'restore_terminal; echo ""; stop_all; ok "Goodbye."; echo ""; exit 0' INT TERM EXIT

    while true; do
        # Print prompt once, read with timeout, erase prompt on timeout
        printf "\r  ${C}❯${RST} Press a key... "

        local key=""
        if IFS= read -rsn1 -t 2 key 2>/dev/null; then
            # Erase the prompt line and move to beginning
            printf "\r\033[K"

            case "$key" in
                d)
                    info "Opening server admin dashboard..."
                    open_browser "http://localhost:${PORT:-8080}/admin/"
                    ;;
                a)
                    info "Opening client admin panel..."
                    open_browser "http://127.0.0.1:9090"
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
                    start_server || true
                    start_client || true
                    show_status
                    ;;
                p)
                    info "Testing SOCKS5 proxy..."
                    local result
                    if result=$(curl -s --connect-timeout 5 --socks5 127.0.0.1:1080 \
                        https://httpbin.org/ip 2>/dev/null); then
                        ok "Proxy working! Response: ${result}"
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
                1)
                    info "Killing server..."
                    stop_server
                    ;;
                2)
                    info "Killing client..."
                    stop_client
                    ;;
                3)
                    info "Killing desktop..."
                    stop_desktop
                    ;;
                0)
                    stop_all
                    ;;
                q)
                    echo ""
                    stop_all
                    ok "Goodbye."
                    echo ""
                    exit 0
                    ;;
                '?')
                    show_controls
                    ;;
                *)
                    # Ignore unknown keys
                    ;;
            esac
        else
            # Timeout — erase the prompt and reprint (single-line overwrite)
            printf "\r\033[K"
        fi
    done
}

# ══════════════════════════════════════════════════════════════════════════════
# Full Stack Start
# ══════════════════════════════════════════════════════════════════════════════

start_full_stack() {
    banner
    load_env

    printf "  ${BD}${W}Preflight Checks${RST}\n"
    sep

    if ! validate_env; then exit 1; fi
    ok "Environment validated"

    ensure_binaries

    mkdir -p "$PID_DIR" "$LOG_DIR"

    sep
    echo ""
    printf "  ${BD}${W}Starting Stack${RST}\n"
    sep

    start_server || exit 1
    echo ""

    local gas="${GAS_URLS:-}"
    if [[ -n "$gas" ]] && [[ "$gas" != *"YOUR_DEPLOYMENT_ID"* ]]; then
        start_client || true
    else
        warn "Skipping client — GAS_URLS not configured"
        dim "Server is running for direct testing"
    fi

    sep
    show_status

    printf "  ${BD}${G}Stack is running!${RST}\n"
    printf "  ${D}Configure browser SOCKS5 proxy → 127.0.0.1:1080${RST}\n"
    echo ""

    interactive_loop
}

# ══════════════════════════════════════════════════════════════════════════════
# Help
# ══════════════════════════════════════════════════════════════════════════════

show_help() {
    printf "${BD}Clever Relay – Local Stack Runner${RST}\n"
    echo ""
    printf "${BD}USAGE:${RST}\n"
    printf "  ${C}./start.sh${RST}              Start full stack with interactive controls\n"
    printf "  ${C}./start.sh ${W}<command>${RST}  Run a specific command\n"
    echo ""
    printf "${BD}COMMANDS:${RST}\n"
    printf "  ${C}--server${RST}      Start only the exit node server\n"
    printf "  ${C}--client${RST}      Start only the SOCKS5 client\n"
    printf "  ${C}--desktop${RST}     Launch the Wails desktop app\n"
    printf "  ${C}--dashboard${RST}   Open server admin dashboard in browser\n"
    printf "  ${C}--panel${RST}       Open client admin panel in browser\n"
    printf "  ${C}--status${RST}      Show running component status\n"
    printf "  ${C}--stop${RST}        Stop all running components\n"
    printf "  ${C}--logs${RST}        Tail both server and client logs\n"
    printf "  ${C}--help${RST}        Show this help\n"
    echo ""
    printf "${BD}INTERACTIVE KEYS:${RST}\n"
    printf "  ${C}d${RST}=server dashboard  ${C}a${RST}=client panel  ${C}w${RST}=desktop  ${C}s${RST}=status\n"
    printf "  ${C}l${RST}=logs  ${C}r${RST}=restart  ${C}p${RST}=test proxy  ${C}h${RST}=health\n"
    printf "  ${Y}1${RST}=kill server  ${Y}2${RST}=kill client  ${Y}3${RST}=kill desktop  ${Y}0${RST}=kill all\n"
    printf "  ${C}q${RST}=quit\n"
    echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

main() {
    cd "$SCRIPT_DIR"
    mkdir -p "$PID_DIR" "$LOG_DIR"

    case "${1:-}" in
        --server|-s)
            banner; load_env; validate_env || exit 1
            ensure_binaries
            start_server || exit 1
            trap 'stop_server; exit 0' INT TERM
            info "Press Ctrl+C to stop"
            tail -f "$SERVER_LOG" 2>/dev/null
            ;;
        --client|-c)
            banner; load_env; validate_env || exit 1
            ensure_binaries
            start_client || exit 1
            trap 'stop_client; exit 0' INT TERM
            info "Press Ctrl+C to stop"
            tail -f "$CLIENT_LOG" 2>/dev/null
            ;;
        --desktop|-w)
            banner; load_env
            launch_desktop
            ;;
        --dashboard|-d)
            load_env
            open_browser "http://localhost:${PORT:-8080}/admin/"
            ;;
        --panel|-a)
            open_browser "http://127.0.0.1:9090"
            ;;
        --status)
            load_env; show_status
            ;;
        --stop)
            stop_all
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
            err "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
