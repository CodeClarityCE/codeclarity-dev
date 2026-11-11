#!/bin/sh
# Sends one command to the broker and exits with the command's status.
# Usage: broker-client.sh <command> [service]
# Env: WAIVE and REASON, a gate waiver that only dump-knowledge accepts.
socket=/run/codeclarity-broker/broker.sock
command=$1
service=$2

# Each value is URL-encoded by curl and stays one quoted argument.
set --
[ -n "$service" ] && set -- "$@" --url-query "service=$service"
[ -n "$WAIVE" ] && set -- "$@" --url-query "waive=$WAIVE"
[ -n "$REASON" ] && set -- "$@" --url-query "reason=$REASON"

curl -sS --no-buffer --unix-socket "$socket" -X POST "$@" "http://broker/$command" | awk '
  /^__BROKER_EXIT__ / { code = $2; next }
  { print; fflush() }
  END { exit (code == "" ? 1 : code) }
'
