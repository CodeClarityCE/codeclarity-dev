# shellcheck shell=sh
# Builds the dev stack with each service's docker-compose.debug.yaml overlay.
. ./compose.sh

compose_debug build ${1:+"$1"}
