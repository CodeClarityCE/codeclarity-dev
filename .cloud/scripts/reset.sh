# shellcheck shell=sh
# Wipes the dev stack: removes its containers and named volumes, then starts it again,
# which reruns every setup job. make reset runs it only with CONFIRM=reset.
#
# Usage: sh reset.sh (from .cloud/scripts)

. ./compose.sh

compose down -v && sh up.sh
