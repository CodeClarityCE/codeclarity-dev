#!/bin/sh
# Builds a small knowledge dump image for the fresh-install and real-stack tests: the 2025
# knowledge and config schemas from the API's migration test fixtures plus one marker CWE row
# and one npm advisory, dumped with a format 1 manifest into the knowledge dump image's Dockerfile.
# Usage: sh knowledge-dump-fixture.sh <image tag>   (needs docker; run from anywhere)
# The marker row is CWE-99999, named "Fresh install fixture". The advisory is OSV's
# GHSA-w9mr-4mfr-499f (CVE-2017-20162, CWE-1333): ms before 2.0.0, so the real-stack journey's
# ms@0.7.1 has exactly one vulnerability; ms@2.1.3, which the fresh-install tests use, has none.
set -eu

tag=${1:?usage: knowledge-dump-fixture.sh <image tag>}
root=$(cd "$(dirname "$0")/../../../.." && pwd)
fixtures="$root/api/test/migrations/fixtures"
dockerfile="$root/.cloud/docker/knowledge-dump/Dockerfile"
postgres=$(sed -n 's/^FROM //p' "$dockerfile")
name="cc-knowledge-fixture-$$"
context=$(mktemp -d)
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$context"' EXIT

docker run -d --name "$name" -e POSTGRES_PASSWORD=fixture "$postgres" >/dev/null
tries=0
until docker exec "$name" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; do
	tries=$((tries + 1))
	[ "$tries" -lt 60 ] || {
		echo "knowledge-dump-fixture: Postgres did not start" >&2
		exit 1
	}
	sleep 1
done

psql() {
	docker exec -i "$name" psql -q -v ON_ERROR_STOP=1 -U postgres "$@"
}

for db in knowledge config; do
	psql -d postgres -c "CREATE DATABASE $db"
	psql -d "$db" <"$fixtures/$db-dump-2025-05-27.sql"
done
psql -d knowledge -c "INSERT INTO cwe (cwe_id, name) VALUES ('CWE-99999', 'Fresh install fixture')"
psql -d knowledge <<'SQL'
INSERT INTO cwe (cwe_id, name) VALUES ('CWE-1333', 'Inefficient Regular Expression Complexity');
INSERT INTO osv (osv_id, schema_version, modified, published, summary, details, cve, aliases, related,
	severity, affected, "references", credits, database_specific, cwes)
VALUES ('GHSA-w9mr-4mfr-499f', '1.9.0', '2025-11-04T16:42:14Z', '2023-01-05T12:30:27Z',
	'Vercel ms Inefficient Regular Expression Complexity vulnerability',
	'The parse function of vercel ms up to 1.x has an inefficient regular expression. Upgrading to version 2.0.0 addresses this issue.',
	'CVE-2017-20162', '["CVE-2017-20162"]', '[]',
	'[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]',
	'[{"package":{"name":"ms","ecosystem":"npm","purl":"pkg:npm/ms"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]',
	'[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2017-20162"},{"type":"PACKAGE","url":"https://github.com/vercel/ms"}]',
	'[]', '{"severity":"MODERATE","github_reviewed":true,"cwe_ids":["CWE-1333"]}', '["CWE-1333"]');
SQL

mkdir "$context/dump"
cp "$root/deployment/scripts/restore-dump.sh" "$context/"
files=""
: >"$context/dump/knowledge-manifest.sha256"
for db in knowledge config; do
	docker exec "$name" pg_dump -U postgres -d "$db" -Fc >"$context/dump/$db.dump"
	size=$(wc -c <"$context/dump/$db.dump" | tr -d ' ')
	sum=$(sha256sum "$context/dump/$db.dump" | cut -d' ' -f1)
	printf '%s  %s\n' "$sum" "$db.dump" >>"$context/dump/knowledge-manifest.sha256"
	files="${files:+$files,}{\"name\":\"$db.dump\",\"database\":\"$db\",\"size\":$size,\"sha256\":\"$sum\"}"
done
version=$(docker exec "$name" psql -XtA -U postgres -c "SHOW server_version")
cat >"$context/dump/knowledge-manifest.json" <<JSON
{
  "format": 1,
  "build_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "postgres_version": "$version",
  "files": [$files],
  "sources": [],
  "migrations": {"knowledge": [], "config": []},
  "gate": {"passed": true, "fixture": true}
}
JSON

DUMP_DIR="$context/dump" sh "$context/restore-dump.sh" verify
docker build -q -f "$dockerfile" -t "$tag" "$context" >/dev/null
echo "knowledge-dump-fixture: built $tag"
