# shellcheck shell=sh
# Runs the one-shot migrate job for every database, or only the ones named.
# The devcontainer runs the same job through the broker (make migrate).
#
# Usage: sh migrate.sh [codeclarity|knowledge|plugins|config]... (from .cloud/scripts)

. ./compose.sh

compose run --rm migrate "$@"
