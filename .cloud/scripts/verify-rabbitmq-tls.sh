#!/usr/bin/env bash
# Verify that RabbitMQ only accepts TLS (encrypted) AMQP connections.
#
# Usage:  sh .cloud/scripts/verify-rabbitmq-tls.sh [container-name]
# If no container name is given, it auto-detects the running rabbitmq container.
#
# Exit code 0 = all checks passed, non-zero = at least one check failed.

set -u

RMQ="${1:-}"
if [ -z "$RMQ" ]; then
  RMQ=$(docker ps --filter "ancestor=rabbitmq" --format '{{.Names}}' | head -1)
  [ -z "$RMQ" ] && RMQ=$(docker ps --format '{{.Names}}' | grep -i rabbitmq | head -1)
fi

if [ -z "$RMQ" ]; then
  echo "✗ Could not find a running rabbitmq container. Pass the name explicitly."
  exit 2
fi

echo "Using container: $RMQ"
fail=0
pass() { printf '  ✓ %s\n' "$1"; }
bad()  { printf '  ✗ %s\n' "$1"; fail=1; }

echo
echo "1) Listeners — TLS-only?"
listeners=$(docker exec "$RMQ" rabbitmq-diagnostics listeners 2>/dev/null)
echo "$listeners" | sed 's/^/     /'
if echo "$listeners" | grep -q "protocol: amqp/ssl"; then
  pass "TLS AMQP listener present (5671 / amqp/ssl)"
else
  bad "No TLS AMQP listener found"
fi
# A plaintext AMQP listener shows 'protocol: amqp,' (no /ssl).
if echo "$listeners" | grep -q "protocol: amqp,"; then
  bad "A PLAINTEXT amqp listener is still enabled"
else
  pass "No plaintext amqp listener"
fi

echo
echo "2) Live connections — all encrypted?"
conns=$(docker exec "$RMQ" rabbitmqctl -q list_connections name peer_host protocol ssl 2>/dev/null)
if [ -z "$conns" ]; then
  echo "     (no client connections currently open)"
else
  echo "$conns" | sed 's/^/     /'
  # The ssl status is the last column (true/false). Count rows explicitly.
  # A non-TLS connection has ssl = false; ignore the header row and any banners
  # (their last field is neither "true" nor "false").
  total=$(echo "$conns" | awk '$NF=="true" || $NF=="false"' | wc -l | tr -d ' ')
  insecure=$(echo "$conns" | awk '$NF=="false"' | wc -l | tr -d ' ')
  if [ "$insecure" -gt 0 ]; then
    bad "$insecure of $total connection(s) are NOT using TLS (ssl = false)"
  elif [ "$total" -gt 0 ]; then
    pass "All $total open connection(s) report ssl = true"
  else
    echo "     (no AMQP client connections detected)"
  fi
fi

echo
echo "3) Negative test — plaintext port 5672 must be refused"
if docker exec "$RMQ" sh -c 'nc -z -w2 127.0.0.1 5672' 2>/dev/null; then
  bad "Port 5672 is OPEN — plaintext is reachable"
else
  pass "Port 5672 refused"
fi

echo
echo "4) Positive test — TLS handshake on 5671 succeeds"
if docker exec "$RMQ" sh -c 'echo | openssl s_client -connect 127.0.0.1:5671 2>/dev/null | grep -q "BEGIN CERTIFICATE\|Cipher"'; then
  pass "TLS handshake on 5671 succeeded"
else
  bad "TLS handshake on 5671 failed"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "✅ RabbitMQ is TLS-only and all connections are encrypted."
else
  echo "❌ One or more checks failed — see above."
fi
exit "$fail"
