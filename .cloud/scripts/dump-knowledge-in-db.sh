# Dumps knowledge and config with a manifest. Runs inside the db container (busybox sh).
# Reads the completeness gate's JSON report on stdin and writes nothing unless it passed.
# Manifest format: docs/knowledge-dump.md.
#
# Usage: sh -c "$(cat dump-knowledge-in-db.sh)" dump-knowledge <gate-report.json
# Env: DUMP_DIR (default /dump), SPLIT_BYTES (default 1900 MiB, under GitHub's 2 GB LFS file limit).

set -eu

DUMP_DIR=${DUMP_DIR:-/dump}
SPLIT_BYTES=${SPLIT_BYTES:-1992294400}
DATABASES="knowledge config"
MANIFEST=knowledge-manifest.json
SUMS=knowledge-manifest.sha256
export PGPASSWORD="${POSTGRES_PASSWORD:-}"

report=$(cat)
if ! printf '%s' "$report" | grep -q '"passed": *true'; then
	echo "dump-knowledge: the completeness gate did not pass, nothing was dumped" >&2
	exit 1
fi

staging="$DUMP_DIR/.dump-knowledge.$$"
mkdir "$staging"
trap 'rm -rf "$staging"' EXIT

query() {
	psql -w -U postgres -d "$1" -XqtA -v ON_ERROR_STOP=1 -c "$2"
}

# One JSON entry per source; row counts come from the gate report that passed.
sources_json() {
	psql -w -U postgres -d knowledge -XqtA -v ON_ERROR_STOP=1 -v gate="$report" <<'SQL'
SET TIME ZONE 'UTC';
WITH checks AS (
  SELECT c->>'name' AS name, c->'actual' AS actual
  FROM jsonb_array_elements(:'gate'::jsonb->'checks') c
)
SELECT coalesce(json_agg(json_build_object(
  'source', s.source,
  'watermark', s.watermark,
  'last_outcome', s.last_outcome,
  'upstream_total', s.upstream_total,
  'rows', (SELECT actual FROM checks WHERE name = s.source || '.rows'),
  'stored_records', (SELECT actual FROM checks WHERE name = s.source || '.upstream_total')
) ORDER BY s.source), '[]')
FROM knowledge_source_sync s;
SQL
}

migrations_json() {
	query "$1" "SELECT coalesce(json_agg(name ORDER BY timestamp, id), '[]') FROM migrations"
}

build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
postgres_version=$(query knowledge "SHOW server_version")
pg_dump_version=$(pg_dump --version)
sources=$(sources_json)
knowledge_migrations=$(migrations_json knowledge)
config_migrations=$(migrations_json config)

sha() {
	sha256sum "$1" | cut -d' ' -f1
}

files=""
: >"$staging/$SUMS"
for db in $DATABASES; do
	name="$db.dump"
	echo "dump-knowledge: dumping $db"
	pg_dump -w -U postgres -d "$db" -Fc -f "$staging/$name"
	size=$(stat -c %s "$staging/$name")
	whole=$(sha "$staging/$name")
	parts=""
	if [ "$size" -gt "$SPLIT_BYTES" ]; then
		# Parts sort in order (part-aaa, part-aab, ...) so cat part-* rebuilds the file.
		(cd "$staging" && split -b "$SPLIT_BYTES" -a 3 "$name" "$name.part-")
		rm "$staging/$name"
		for part in "$staging/$name.part-"*; do
			part_name=${part##*/}
			part_sha=$(sha "$part")
			printf '%s  %s\n' "$part_sha" "$part_name" >>"$staging/$SUMS"
			part_entry=$(printf '{"name":"%s","size":%s,"sha256":"%s"}' "$part_name" "$(stat -c %s "$part")" "$part_sha")
			parts="${parts:+$parts,}$part_entry"
		done
	else
		printf '%s  %s\n' "$whole" "$name" >>"$staging/$SUMS"
	fi
	entry=$(printf '{"name":"%s","database":"%s","size":%s,"sha256":"%s","parts":[%s]}' "$name" "$db" "$size" "$whole" "$parts")
	files="${files:+$files,}$entry"
done

cat >"$staging/$MANIFEST" <<JSON
{
  "format": 1,
  "build_date": "$build_date",
  "postgres_version": "$postgres_version",
  "pg_dump_version": "$pg_dump_version",
  "split_bytes": $SPLIT_BYTES,
  "files": [$files],
  "sources": $sources,
  "migrations": {"knowledge": $knowledge_migrations, "config": $config_migrations},
  "gate": $report
}
JSON

# Replace the previous dump only once everything is ready.
for db in $DATABASES; do
	rm -f "$DUMP_DIR/$db.dump" "$DUMP_DIR/$db.dump.part-"*
done
rm -f "$DUMP_DIR/$MANIFEST" "$DUMP_DIR/$SUMS"
mv "$staging"/* "$DUMP_DIR/"
echo "dump-knowledge: wrote $(cd "$DUMP_DIR" && cut -d' ' -f3 "$SUMS" | tr '\n' ' ')and $MANIFEST"
