PG_DB_USER="postgres"
PG_DB_PASSWORD="!ChangeMe!"
PG_DB_HOST="127.0.0.1"
PG_DB_NAME="codeclarity"
NVD_API_KEY=""
NPM_URL="https://registry.npmjs.org/"

# AMQP — host-run make targets (knowledge-setup/knowledge-update) reach the
# RabbitMQ container via its published port on localhost. RabbitMQ is TLS-only
# on 5671 (plaintext 5672 disabled), so connect with amqps. The dev cert is
# issued for the in-network hostname "rabbitmq", so SSLMODE=require is used to
# encrypt without hostname verification (InsecureSkipVerify) when dialing
# 127.0.0.1. (Containers use AMQP_HOST=rabbitmq from .env.dev instead.)
AMQP_PROTOCOL="amqps"
AMQP_HOST="127.0.0.1"
AMQP_PORT="5671"
AMQP_SSLMODE="require"
AMQP_USER="guest"
AMQP_PASSWORD="guest"