# shellcheck shell=sh
# Ensure the dev RabbitMQ TLS certificate exists before starting (idempotent).
sh ../docker/scripts/generate-rabbitmq-dev-certs.sh
# The shared pnpm store the api and frontend containers mount (idempotent).
docker volume create pnpm-store >/dev/null

. ./compose.sh

compose up -d ${1:+"$1"}
