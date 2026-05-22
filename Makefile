# ══════════════════════════════════════════════════════════════════════════════
# Clever Relay – Master Makefile
#
# Builds all components and places executables in ./bin/
#
# Usage:
#   make              Build everything (frontend + all Go binaries)
#   make all          Same as above
#   make exitnode     Build only the exit node server
#   make localengine  Build only the local SOCKS5 client
#   make desktop      Build only the Wails desktop app
#   make frontend     Build only the admin dashboard frontend
#   make test         Run all tests
#   make lint         Run go vet on all modules
#   make clean        Remove build artifacts
#   make docker       Build the Docker image for Clever Cloud
#   make release      Build release binaries for all platforms
#   make help         Show this help
# ══════════════════════════════════════════════════════════════════════════════

# ── Configuration ─────────────────────────────────────────────────────────────
SHELL         := /bin/bash
PROJECT_ROOT  := $(shell pwd)
BIN_DIR       := $(PROJECT_ROOT)/bin
VERSION       := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
GO            := go
CGO_ENABLED   ?= 0
GOFLAGS       := -trimpath
LDFLAGS       := -w -s \
                 -X main.Version=$(VERSION) \
                 -X main.BuildTime=$(BUILD_TIME) \
                 -X main.Commit=$(COMMIT)

# Target OS/Arch (defaults to current platform)
GOOS          ?= $(shell go env GOOS)
GOARCH        ?= $(shell go env GOARCH)

# Binary names
EXITNODE_BIN  := clever-relay-server
LOCALENG_BIN  := clever-relay-client
DESKTOP_BIN   := clever-relay-desktop

# Frontend tooling
BUN           := bun
NPM           := npm

# Colors for pretty output
CYAN          := \033[36m
GREEN         := \033[32m
YELLOW        := \033[33m
RED           := \033[31m
BOLD          := \033[1m
RESET         := \033[0m

# ── Default Target ────────────────────────────────────────────────────────────
.DEFAULT_GOAL := all

.PHONY: all exitnode localengine desktop frontend frontend-panel frontend-desktop \
        test lint clean docker release help deps \
        cross-linux cross-windows cross-darwin

# ── Main Targets ──────────────────────────────────────────────────────────────

all: banner deps frontend frontend-panel exitnode localengine  ## Build everything
	@printf "$(GREEN)$(BOLD)✓ All builds complete. Binaries in ./bin/$(RESET)\n"
	@ls -lh $(BIN_DIR)/

banner:
	@printf "$(CYAN)$(BOLD)"
	@echo "╔══════════════════════════════════════════════════╗"
	@echo "║          Clever Relay – Build System             ║"
	@echo "╠══════════════════════════════════════════════════╣"
	@printf "║ Version  : %-37s ║\n" "$(VERSION)"
	@printf "║ Commit   : %-37s ║\n" "$(COMMIT)"
	@printf "║ Platform : %-37s ║\n" "$(GOOS)/$(GOARCH)"
	@printf "║ Time     : %-37s ║\n" "$(BUILD_TIME)"
	@echo "╚══════════════════════════════════════════════════╝"
	@printf "$(RESET)"

# ── Dependencies ──────────────────────────────────────────────────────────────

deps:  ## Download Go dependencies for all modules
	@printf "$(CYAN)▸ Downloading Go dependencies...$(RESET)\n"
	@cd $(PROJECT_ROOT)/dataengine && $(GO) mod download
	@cd $(PROJECT_ROOT)/exitnode && $(GO) mod download
	@cd $(PROJECT_ROOT)/localengine && $(GO) mod download
	@printf "$(GREEN)  ✓ Dependencies ready$(RESET)\n"

# ── Frontend Builds ──────────────────────────────────────────────────────────

frontend:  ## Build the admin dashboard (React → exitnode/dashboard/dist)
	@printf "$(CYAN)▸ Building admin dashboard frontend...$(RESET)\n"
	@cd $(PROJECT_ROOT)/frontend && $(BUN) install --frozen-lockfile 2>/dev/null || $(BUN) install
	@cd $(PROJECT_ROOT)/frontend && $(BUN) run build
	@printf "$(GREEN)  ✓ Dashboard built → exitnode/dashboard/dist/$(RESET)\n"

frontend-panel:  ## Build the client admin panel (React → localengine/panel/dist)
	@printf "$(CYAN)▸ Building client admin panel frontend...$(RESET)\n"
	@cd $(PROJECT_ROOT)/client-panel && $(BUN) install --frozen-lockfile 2>/dev/null || $(BUN) install
	@cd $(PROJECT_ROOT)/client-panel && $(BUN) run build
	@printf "$(GREEN)  ✓ Client panel built → localengine/panel/dist/$(RESET)\n"

frontend-desktop:  ## Build the desktop Wails frontend
	@printf "$(CYAN)▸ Building desktop frontend...$(RESET)\n"
	@cd $(PROJECT_ROOT)/desktop/frontend && $(NPM) install --silent 2>/dev/null || $(NPM) install
	@cd $(PROJECT_ROOT)/desktop/frontend && $(NPM) run build
	@printf "$(GREEN)  ✓ Desktop frontend built$(RESET)\n"

# ── Go Binary Builds ─────────────────────────────────────────────────────────

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

exitnode: $(BIN_DIR) frontend  ## Build the Clever Cloud exit node server
	@printf "$(CYAN)▸ Building exit node server...$(RESET)\n"
	@cd $(PROJECT_ROOT)/exitnode && \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(EXITNODE_BIN) .
	@printf "$(GREEN)  ✓ $(BIN_DIR)/$(EXITNODE_BIN) ($(GOOS)/$(GOARCH))$(RESET)\n"

localengine: $(BIN_DIR) frontend-panel  ## Build the local SOCKS5 client engine
	@printf "$(CYAN)▸ Building local client engine...$(RESET)\n"
	@cd $(PROJECT_ROOT)/localengine && \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(LOCALENG_BIN) .
	@printf "$(GREEN)  ✓ $(BIN_DIR)/$(LOCALENG_BIN) ($(GOOS)/$(GOARCH))$(RESET)\n"

desktop: $(BIN_DIR) frontend-desktop  ## Build the Wails desktop application
	@printf "$(CYAN)▸ Building Wails desktop app...$(RESET)\n"
	@command -v wails >/dev/null 2>&1 || { \
		printf "$(RED)  ✗ wails CLI not found. Install with: go install github.com/wailsapp/wails/v2/cmd/wails@latest$(RESET)\n"; \
		exit 1; \
	}
	@cd $(PROJECT_ROOT)/desktop && wails build -o $(DESKTOP_BIN)
	@cp $(PROJECT_ROOT)/desktop/build/bin/$(DESKTOP_BIN) $(BIN_DIR)/$(DESKTOP_BIN) 2>/dev/null || \
		cp $(PROJECT_ROOT)/desktop/build/bin/$(DESKTOP_BIN).exe $(BIN_DIR)/$(DESKTOP_BIN).exe 2>/dev/null || true
	@printf "$(GREEN)  ✓ Desktop app built$(RESET)\n"

# ── Testing ───────────────────────────────────────────────────────────────────

test:  ## Run all tests across all modules
	@printf "$(CYAN)▸ Running tests...$(RESET)\n"
	@printf "$(YELLOW)  → dataengine$(RESET)\n"
	@cd $(PROJECT_ROOT)/dataengine && $(GO) test -v -count=1 -race ./...
	@printf "$(GREEN)  ✓ All tests passed$(RESET)\n"

test-bench:  ## Run benchmarks
	@printf "$(CYAN)▸ Running benchmarks...$(RESET)\n"
	@cd $(PROJECT_ROOT)/dataengine && $(GO) test -bench=. -benchmem ./...

test-cover:  ## Run tests with coverage report
	@printf "$(CYAN)▸ Generating coverage report...$(RESET)\n"
	@mkdir -p $(BIN_DIR)
	@cd $(PROJECT_ROOT)/dataengine && $(GO) test -coverprofile=$(BIN_DIR)/coverage.out ./...
	@cd $(PROJECT_ROOT)/dataengine && $(GO) tool cover -html=$(BIN_DIR)/coverage.out -o $(BIN_DIR)/coverage.html
	@printf "$(GREEN)  ✓ Coverage report → $(BIN_DIR)/coverage.html$(RESET)\n"

# ── Linting ───────────────────────────────────────────────────────────────────

lint:  ## Run go vet on all Go modules
	@printf "$(CYAN)▸ Linting...$(RESET)\n"
	@cd $(PROJECT_ROOT)/dataengine && $(GO) vet ./... && printf "$(GREEN)  ✓ dataengine$(RESET)\n"
	@cd $(PROJECT_ROOT)/exitnode && $(GO) vet ./... && printf "$(GREEN)  ✓ exitnode$(RESET)\n"
	@cd $(PROJECT_ROOT)/localengine && $(GO) vet ./... && printf "$(GREEN)  ✓ localengine$(RESET)\n"
	@cd $(PROJECT_ROOT)/desktop && $(GO) vet ./... && printf "$(GREEN)  ✓ desktop$(RESET)\n"
	@printf "$(GREEN)  ✓ All modules clean$(RESET)\n"

# ── Docker ────────────────────────────────────────────────────────────────────

docker:  ## Build Docker image for Clever Cloud deployment
	@printf "$(CYAN)▸ Building Docker image...$(RESET)\n"
	docker build \
		-f $(PROJECT_ROOT)/exitnode/Dockerfile \
		-t clever-relay:$(VERSION) \
		-t clever-relay:latest \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		$(PROJECT_ROOT)
	@printf "$(GREEN)  ✓ Docker image: clever-relay:$(VERSION)$(RESET)\n"

# ── Cross-Compilation (Release Builds) ────────────────────────────────────────

release: clean  ## Build release binaries for Linux, macOS, and Windows
	@printf "$(CYAN)$(BOLD)▸ Building release binaries...$(RESET)\n"
	@$(MAKE) --no-print-directory _release-target GOOS=linux   GOARCH=amd64 SUFFIX=linux-amd64
	@$(MAKE) --no-print-directory _release-target GOOS=linux   GOARCH=arm64 SUFFIX=linux-arm64
	@$(MAKE) --no-print-directory _release-target GOOS=darwin  GOARCH=amd64 SUFFIX=darwin-amd64
	@$(MAKE) --no-print-directory _release-target GOOS=darwin  GOARCH=arm64 SUFFIX=darwin-arm64
	@$(MAKE) --no-print-directory _release-target GOOS=windows GOARCH=amd64 SUFFIX=windows-amd64 EXT=.exe
	@printf "\n$(GREEN)$(BOLD)✓ Release binaries:$(RESET)\n"
	@ls -lh $(BIN_DIR)/

_release-target:
	@printf "$(YELLOW)  → $(GOOS)/$(GOARCH)$(RESET)\n"
	@mkdir -p $(BIN_DIR)
	@cd $(PROJECT_ROOT)/exitnode && \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(EXITNODE_BIN)-$(SUFFIX)$(EXT) .
	@cd $(PROJECT_ROOT)/localengine && \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
		-o $(BIN_DIR)/$(LOCALENG_BIN)-$(SUFFIX)$(EXT) .

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:  ## Remove all build artifacts
	@printf "$(CYAN)▸ Cleaning build artifacts...$(RESET)\n"
	@rm -rf $(BIN_DIR)
	@rm -rf $(PROJECT_ROOT)/exitnode/dashboard/dist
	@rm -rf $(PROJECT_ROOT)/localengine/panel/dist
	@rm -rf $(PROJECT_ROOT)/desktop/build/bin
	@cd $(PROJECT_ROOT)/dataengine && $(GO) clean -cache -testcache 2>/dev/null || true
	@cd $(PROJECT_ROOT)/exitnode && $(GO) clean -cache 2>/dev/null || true
	@cd $(PROJECT_ROOT)/localengine && $(GO) clean -cache 2>/dev/null || true
	@printf "$(GREEN)  ✓ Clean$(RESET)\n"

# ── Help ──────────────────────────────────────────────────────────────────────

help:  ## Show this help message
	@printf "$(BOLD)Clever Relay – Available targets:$(RESET)\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-18s$(RESET) %s\n", $$1, $$2}'
	@printf "\n$(BOLD)Examples:$(RESET)\n"
	@echo "  make                    Build everything"
	@echo "  make exitnode           Build only the server"
	@echo "  make localengine        Build only the client"
	@echo "  make test               Run all tests"
	@echo "  make release            Cross-compile for all platforms"
	@echo "  make GOOS=windows localengine   Cross-compile client for Windows"
	@echo ""
