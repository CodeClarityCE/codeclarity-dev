#!/bin/sh
# Sends one command to the broker and exits with the command's status.
# Usage: broker-client.sh <command> [service]
socket=/run/codeclarity-broker/broker.sock
url="http://broker/$1"
[ -n "$2" ] && url="$url?service=$2"

curl -sS --no-buffer --unix-socket "$socket" -X POST "$url" | awk '
  /^__BROKER_EXIT__ / { code = $2; next }
  { print; fflush() }
  END { exit (code == "" ? 1 : code) }
'
