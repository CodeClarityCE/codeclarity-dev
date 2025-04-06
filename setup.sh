#!/bin/bash

# Verify the presence of required commands
if ! command -v curl &>/dev/null; then
    echo "Error: curl is not installed."
    exit 1
fi

if ! command -v make &>/dev/null; then
    echo "Error: make is not installed."
    exit 1
fi

if ! command -v docker &>/dev/null || ! command -v docker-compose &>/dev/null; then
    echo "Error: docker or docker-compose is not installed."
    exit 1
fi

echo "All required commands are installed."

if [ -f ".git" ] || [ -d ".git" ]; then
    echo ".git found. Skipping repository clone."
else
    git clone https://github.com/CodeClarityCE/codeclarity-dev.git --recursive
    cd codeclarity-dev
fi

# Ensure all services are down
make down
# Start DB container
make build
cd .cloud/scripts && sh up.sh db && cd -
# Download dumps
make download-dumps
# Create Postgre databases
make knowledge-setup
# Restore database content from dumps
make restore-database
# Start all containers
make up

echo "Installation successful, you can now visit: https://localhost:443"
echo "You can connect using the following credentials:"
echo "- login: john.doe@codeclarity.io"
echo "- password: ThisIs4Str0ngP4ssW0rd?"