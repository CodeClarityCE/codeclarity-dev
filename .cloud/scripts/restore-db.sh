# Verifies the dumps in deployment/dump against their manifest, or restores one of them,
# by running deployment/scripts/restore-dump.sh inside the db container.
#
# Usage (from .cloud/scripts):
#   sh restore-db.sh verify
#   sh restore-db.sh <dump> [<database>]   (database defaults to the dump name)
# Env: DEPLOYMENT_DIR (default ../../deployment).

DEPLOYMENT_DIR=${DEPLOYMENT_DIR:-../../deployment}

compose() {
	docker compose -f ../docker/docker-compose.yaml \
		-f ../../api/.cloud/docker/docker-compose.yaml \
		-f ../../frontend/.cloud/docker/docker-compose.yaml \
		-f ../../backend/services/packageFollower/.cloud/docker/docker-compose.yaml \
		-f ../../backend/services/notifier/.cloud/docker/docker-compose.yaml \
		-f ../../backend/services/downloader/.cloud/docker/docker-compose.yaml \
		-f ../../backend/services/dispatcher/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/codeql/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/license-finder/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/js-patching/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/js-sbom/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/vuln-finder/.cloud/docker/docker-compose.yaml \
		-f ../../backend/plugins/php-sbom/.cloud/docker/docker-compose.yaml "$@"
}

script=$(cat "$DEPLOYMENT_DIR/scripts/restore-dump.sh") || exit 1

if [ "$1" = verify ]; then
	compose exec -T db sh -c "$script" restore-dump verify
else
	compose exec -T db sh -c "$script" restore-dump restore "$1" "${2:-$1}"
fi
