#!/bin/bash
# Generate a self-signed RabbitMQ server certificate for the dev environment.
# Dev clients connect with AMQP_SSLMODE=require (skip-verify), so no CA distribution
# is needed — only the server needs a certificate to enable the TLS listener.
set -e

# Resolve the certs dir relative to the dev compose file (.cloud/docker/).
CERT_DIR="${1:-$(dirname "$0")/../certs/rabbitmq}"
SERVER_DAYS="${2:-3650}"

# Idempotent: skip if a server cert already exists.
if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
  echo "Dev RabbitMQ certificate already present in $CERT_DIR — skipping."
  exit 0
fi

mkdir -p "$CERT_DIR"

echo "Generating self-signed dev RabbitMQ certificate in $CERT_DIR..."

SAN_EXT=$(mktemp)
printf "subjectAltName=DNS:rabbitmq,DNS:localhost,IP:127.0.0.1\n" > "$SAN_EXT"
openssl req -new -x509 -days "$SERVER_DAYS" -nodes -text \
  -subj "/CN=rabbitmq" \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.crt" \
  -addext "subjectAltName=DNS:rabbitmq,DNS:localhost,IP:127.0.0.1" 2>/dev/null
rm -f "$SAN_EXT"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo "Dev RabbitMQ certificate generated: $CERT_DIR/server.{crt,key}"
