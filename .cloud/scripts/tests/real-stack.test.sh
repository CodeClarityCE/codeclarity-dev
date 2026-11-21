#!/bin/sh
# Tests the real-stack e2e override: the dev stack's Compose file list never names it, and merged
# over the deployment file it starts only the setup jobs and the services the journey needs.
# The service check needs docker compose and is skipped without it.
# Usage: sh .cloud/scripts/tests/real-stack.test.sh
root=$(cd "$(dirname "$0")/../../.." && pwd)
override=.cloud/scripts/tests/real-stack/docker-compose.yaml
passed=0 failed=0 skipped=0

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
	fi
}

result=ok
[ -f "$root/$override" ] || result=bad
check "the override exists" $result

result=ok
grep -v '^#' "$root/.cloud/docker/compose-files.txt" | grep -q 'real-stack' && result=bad
check "the dev stack's Compose file list does not name the override" $result

if docker compose version >/dev/null 2>&1 && [ -f "$root/deployment/docker-compose.yaml" ]; then
	want="api db default-analyzer frontend generate-secrets knowledge-restore migrate pgbouncer plugin-js-sbom
plugin-license-finder plugin-php-sbom plugin-vuln-finder rabbitmq service-dispatcher service-downloader
service-follower version-check vulnerability-instance-backfill"
	result=ok
	got=$(docker compose --project-directory "$root/deployment" -f "$root/deployment/docker-compose.yaml" \
		-f "$root/$override" config --services | sort | tr '\n' ' ') || result=bad
	[ "$got" = "$(echo "$want" | tr '\n' ' ' | tr ' ' '\n' | sort | tr '\n' ' ')" ] || result=bad
	check "merged over the deployment file it starts only the journey's services (got: $got)" $result
else
	skipped=$((skipped + 1))
	echo "skip the service check needs docker compose and the deployment submodule"
fi

echo "$passed passed, $failed failed, $skipped skipped"
[ "$failed" -eq 0 ]
