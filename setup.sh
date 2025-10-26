#!/bin/bash

# Color codes for better output (using printf for portability)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Setup logging
SETUP_LOG="setup.log"
ERROR_LOG="setup-errors.log"

# Clear previous logs
> "$SETUP_LOG"
> "$ERROR_LOG"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$SETUP_LOG"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$ERROR_LOG"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$SETUP_LOG"
}

# Helper function for formatted output using printf for cross-platform compatibility
print_header() {
    printf "\n${BLUE}${BOLD}=== %s ===${NC}\n" "$1"
    log "=== $1 ==="
}

print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
    log "SUCCESS: $1"
}

print_info() {
    printf "${BLUE}ℹ${NC} %s\n" "$1"
    log "INFO: $1"
}

print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
    log_error "$1"
}

print_progress() {
    printf "${YELLOW}⚡${NC} %s" "$1"
}

# Verify the presence of required commands
print_header "Checking Requirements"

if ! command -v curl &>/dev/null; then
    print_error "curl is not installed."
    exit 1
fi

if ! command -v make &>/dev/null; then
    print_error "make is not installed."
    exit 1
fi

if ! command -v docker &>/dev/null || ! command -v docker compose &>/dev/null; then
    print_error "docker or docker compose is not installed."
    exit 1
fi

# Check for yarn - either directly installed or via corepack
if ! command -v yarn &>/dev/null; then
    print_error "yarn is not installed."
    print_info "You can install it using one of these methods:"
    print_info "  1. Using corepack (recommended): corepack enable"
    print_info "  2. Using npm: npm install -g yarn"
    print_info "  3. Using Homebrew: brew install yarn"
    exit 1
fi

print_success "All required commands are installed"

# Repository check
print_header "Repository Setup"
if [ -f ".git" ] || [ -d ".git" ]; then
    print_info "Git repository found. Skipping clone."
else
    print_progress "Cloning repository with submodules..."
    if git clone https://github.com/CodeClarityCE/codeclarity-dev.git --recursive >>"$SETUP_LOG" 2>&1; then
        cd codeclarity-dev || exit 1
        printf "\r"
        print_success "Repository cloned with submodules       "
    else
        printf "\r"
        print_error "Failed to clone repository - check $SETUP_LOG"
        exit 1
    fi
fi

# Development environment setup
print_header "Development Environment Setup"

print_progress "Stopping any running services..."
if make down >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "Services stopped                    "
else
    printf "\r"
    print_error "Failed to stop services - check $SETUP_LOG"
fi

print_progress "Building Docker images..."
if make build >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "Docker images built                 "
else
    printf "\r"
    print_error "Failed to build Docker images - check $SETUP_LOG"
    exit 1
fi

print_progress "Starting database container..."
if cd .cloud/scripts && sh up.sh db >>"$SETUP_LOG" 2>&1 && cd - >/dev/null 2>&1; then
    printf "\r"
    print_success "Database container started          "
else
    printf "\r"
    print_error "Failed to start database container - check $SETUP_LOG"
    exit 1
fi

print_header "Database Setup"

print_progress "Downloading database dumps..."
if make download-dumps >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "Database dumps downloaded           "
else
    printf "\r"
    print_error "Failed to download database dumps - check $SETUP_LOG"
    exit 1
fi

printf "${YELLOW}⚡${NC} Setting up knowledge database (interactive)...\n"
printf "${BLUE}ℹ${NC} This step may ask if you want to recreate existing databases\n"
if make knowledge-setup 2>&1 | tee -a "$SETUP_LOG"; then
    print_success "Knowledge database configured"
else
    print_error "Failed to setup knowledge database - check $SETUP_LOG"
    exit 1
fi

print_progress "Restoring database content..."
if make restore-database >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "Database content restored           "
else
    printf "\r"
    print_error "Failed to restore database - check $SETUP_LOG"
    exit 1
fi

print_progress "Applying database migrations..."
if make migrate >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "Database migrations applied          "
else
    printf "\r"
    print_error "Database migrations failed - check $SETUP_LOG"
    exit 1
fi

print_header "Starting Services"

print_progress "Starting all development services..."
if make up >>"$SETUP_LOG" 2>&1; then
    printf "\r"
    print_success "All services started                "
else
    printf "\r"
    print_error "Failed to start services - check $SETUP_LOG"
    exit 1
fi

# Wait a moment for services to stabilize
print_progress "Waiting for services to initialize..."
sleep 3
printf "\r"
print_success "Services initialized                "

# Final message
print_header "Development Environment Ready"
printf "${GREEN}${BOLD}Success!${NC} CodeClarity development environment is running.\n"
printf "\n"
printf "🌐 ${BOLD}Web Interface:${NC} ${BLUE}https://localhost:443${NC}\n"
printf "📧 ${BOLD}Default login:${NC} john.doe@codeclarity.io\n"
printf "🔐 ${BOLD}Default password:${NC} ThisIs4Str0ngP4ssW0rd?\n"
printf "\n"
printf "${BLUE}${BOLD}Development Environment Notes:${NC}\n"
printf "• Schema changes applied automatically during development\n"
printf "\n"
printf "${YELLOW}ℹ${NC} Use 'make logs' to monitor service logs\n"
printf "${YELLOW}ℹ${NC} Use 'make down' to stop all services\n"
printf "${YELLOW}ℹ${NC} Setup logs available in: $SETUP_LOG\n"
if [ -s "$ERROR_LOG" ]; then
    printf "${RED}⚠${NC} Errors logged in: $ERROR_LOG\n"
fi