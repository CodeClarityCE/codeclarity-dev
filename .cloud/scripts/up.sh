# shellcheck shell=sh
# Ensure the dev RabbitMQ TLS certificate exists before starting (idempotent).
sh ../docker/scripts/generate-rabbitmq-dev-certs.sh

. ./compose.sh

compose up -d ${1:+"$1"}
