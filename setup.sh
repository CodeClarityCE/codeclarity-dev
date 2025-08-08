#!/bin/bash

# Color codes for better output (using printf for portability)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Helper function for formatted output using printf for cross-platform compatibility
print_header() {
    printf "\n${BLUE}${BOLD}=== %s ===${NC}\n" "$1"
}

print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

print_info() {
    printf "${BLUE}ℹ${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
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

print_success "All required commands are installed"

# Repository check
print_header "Repository Setup"
if [ -f ".git" ] || [ -d ".git" ]; then
    print_info "Git repository found. Skipping clone."
else
    print_progress "Cloning repository with submodules..."
    git clone https://github.com/CodeClarityCE/codeclarity-dev.git --recursive >/dev/null 2>&1
    cd codeclarity-dev
    printf "\r"
    print_success "Repository cloned with submodules       "
fi

# Development environment setup
print_header "Development Environment Setup"

print_progress "Stopping any running services..."
make down >/dev/null 2>&1
printf "\r"
print_success "Services stopped                    "

print_progress "Building Docker images..."
make build >/dev/null 2>&1
printf "\r"
print_success "Docker images built                 "

print_progress "Starting database container..."
cd .cloud/scripts && sh up.sh db >/dev/null 2>&1 && cd - >/dev/null 2>&1
printf "\r"
print_success "Database container started          "

print_header "Database Setup"

print_progress "Downloading database dumps..."
make download-dumps >/dev/null 2>&1
printf "\r"
print_success "Database dumps downloaded           "

printf "${YELLOW}⚡${NC} Setting up knowledge database (interactive)...\n"
printf "${BLUE}ℹ${NC} This step may ask if you want to recreate existing databases\n"
make knowledge-setup
print_success "Knowledge database configured"

print_progress "Restoring database content..."
make restore-database >/dev/null 2>&1
printf "\r"
print_success "Database content restored           "

print_header "Starting Services"

print_progress "Starting all development services..."
make up >/dev/null 2>&1
printf "\r"
print_success "All services started                "

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