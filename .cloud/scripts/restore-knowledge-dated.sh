# Restores the knowledge and config databases from a dated dump pair
# (deployment/dump/knowledge-<LABEL>.dump + config-<LABEL>.dump) produced by
# dump-db-dated.sh. Restores knowledge and config ONLY — never codeclarity.
#
# config MUST travel with knowledge: the config row's *_last columns are the
# provenance the API reports and nvd_last is the incremental-fetch cursor, so
# a rung's config state has to match the knowledge state it was dumped with.
#
# Usage: sh restore-knowledge-dated.sh <LABEL>

LABEL="$1"

if [ -z "$LABEL" ]; then
	echo "Usage: sh restore-knowledge-dated.sh <LABEL>" >&2
	exit 1
fi

case "$LABEL" in
	*[!A-Za-z0-9._-]*)
		echo "Error: LABEL must only contain [A-Za-z0-9._-] (got '$LABEL')" >&2
		exit 1
		;;
esac

DUMP_DIR=../../deployment/dump

. ./compose.sh

for db in knowledge config; do
	if [ ! -f "$DUMP_DIR/$db-$LABEL.dump" ]; then
		echo "Error: $DUMP_DIR/$db-$LABEL.dump not found (run dump-db-dated.sh $LABEL first)" >&2
		exit 1
	fi
done

compose \
	exec db sh -c "pg_restore -l /dump/knowledge-$LABEL.dump > /dump/knowledge-$LABEL.list && PGPASSWORD=\$POSTGRES_PASSWORD pg_restore -w -U postgres -d knowledge --clean --if-exists -L /dump/knowledge-$LABEL.list /dump/knowledge-$LABEL.dump" || exit 1

# Marks the database so the daemon refuses to update it and filter-asof accepts it.
compose exec -T db sh -c "PGPASSWORD=\$POSTGRES_PASSWORD psql -v ON_ERROR_STOP=1 -w -U postgres -d knowledge -v label='$LABEL'" <mark-dated-restore.sql || exit 1

compose \
	exec db sh -c "pg_restore -l /dump/config-$LABEL.dump > /dump/config-$LABEL.list && PGPASSWORD=\$POSTGRES_PASSWORD pg_restore -w -U postgres -d config --clean --if-exists -L /dump/config-$LABEL.list /dump/config-$LABEL.dump" || exit 1

echo "Restored knowledge and config from label '$LABEL'."
echo "Reminder: restart the services (make down && make up) so pooled connections and caches re-read the new database state."
