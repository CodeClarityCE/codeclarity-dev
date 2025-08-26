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
	exec db sh -c "pg_restore -l /dump/knowledge.dump > /dump/knowledge.list && pg_restore -U postgres -d knowledge_test -L /dump/knowledge.list /dump/knowledge.dump"

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
	exec db sh -c "pg_restore -l /dump/config.dump > /dump/config.list && pg_restore -U postgres -d config_test -L /dump/config.list /dump/config.dump"

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
	exec db sh -c "pg_restore -l /dump/codeclarity.dump > /dump/codeclarity.list && pg_restore -U postgres -d codeclarity_test -L /dump/codeclarity.list /dump/codeclarity.dump"