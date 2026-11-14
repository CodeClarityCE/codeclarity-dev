# shellcheck shell=sh
# Dumps one database to deployment/dump/<db>.dump. knowledge and config go through
# dump-knowledge.sh instead, so they are only dumped after the completeness gate passes.
case "$1" in
knowledge | config)
	echo "Error: dump $1 with make dump-knowledge, which runs the completeness gate first" >&2
	exit 1
	;;
esac

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
	-f ../../backend/plugins/php-sbom/.cloud/docker/docker-compose.yaml \
	exec db sh -c "PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d $1 -Fc > /dump/$1.dump"