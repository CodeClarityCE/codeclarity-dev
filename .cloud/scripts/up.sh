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
	up -d $1