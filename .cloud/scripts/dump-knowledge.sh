# Dumps knowledge and config to deployment/dump with a manifest, only if the completeness gate passes.
# The devcontainer runs the same two steps through the broker (make dump-knowledge).
#
# Usage: sh dump-knowledge.sh (from .cloud/scripts)
# Env: API_DIR (default ../../api), whose migrations the gate expects.

API_DIR=${API_DIR:-../../api}

. ./compose.sh

# api_migrations lists one API migrations folder's classes, oldest first, comma-separated.
# Empty when the folder is missing, so the gate falls back to its embedded list.
api_migrations() {
	for file in "$API_DIR/src/migrations/$1"/*.ts; do
		[ -f "$file" ] && sed -n 's/^export class \([A-Za-z0-9_]*\).*/\1/p' "$file" | head -n 1
	done | paste -s -d, -
}

report=$(mktemp)
trap 'rm -f "$report"' EXIT

echo "Running the knowledge completeness gate"
compose exec -T -w /codeclarity/services/knowledge \
	-e KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE="$(api_migrations knowledge)" \
	-e KNOWLEDGE_EXPECTED_MIGRATIONS_CONFIG="$(api_migrations config)" \
	service-package-follower \
	go run . -knowledge -action validate -read-only >"$report"
status=$?
cat "$report"
if [ "$status" -ne 0 ]; then
	echo "Error: the completeness gate failed (exit $status), nothing was dumped" >&2
	exit 1
fi

compose exec -T db sh -c "$(cat dump-knowledge-in-db.sh)" dump-knowledge <"$report" || exit 1
