# Dumps knowledge and config to deployment/dump with a manifest, only if the completeness gate passes.
# The devcontainer runs the same two steps through the broker (make dump-knowledge).
#
# Usage: sh dump-knowledge.sh (from .cloud/scripts)

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

report=$(mktemp)
trap 'rm -f "$report"' EXIT

echo "Running the knowledge completeness gate"
compose exec -T -w /codeclarity/services/knowledge service-package-follower \
	go run . -knowledge -action validate -read-only >"$report"
status=$?
cat "$report"
if [ "$status" -ne 0 ]; then
	echo "Error: the completeness gate failed (exit $status), nothing was dumped" >&2
	exit 1
fi

compose exec -T db sh -c "$(cat dump-knowledge-in-db.sh)" dump-knowledge <"$report" || exit 1
