# shellcheck shell=sh
# Starts the dev stack with each service's docker-compose.debug.yaml overlay.
. ./compose.sh

compose_debug up -d ${1:+"$1"}
