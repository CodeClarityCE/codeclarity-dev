# shellcheck shell=sh
# Dumps dated snapshots of the knowledge and config databases for the ladder
# experiment. Produces deployment/dump/knowledge-<LABEL>.dump and
# deployment/dump/config-<LABEL>.dump. Refuses to overwrite existing dumps.
#
# Usage: sh dump-db-dated.sh <LABEL>

LABEL="$1"

if [ -z "$LABEL" ]; then
	echo "Usage: sh dump-db-dated.sh <LABEL>" >&2
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
	if [ -e "$DUMP_DIR/$db-$LABEL.dump" ]; then
		echo "Error: $DUMP_DIR/$db-$LABEL.dump already exists, refusing to overwrite" >&2
		exit 1
	fi
done

compose exec db sh -c "PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d knowledge -Fc > /dump/knowledge-$LABEL.dump" || exit 1

compose exec db sh -c "PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d config -Fc > /dump/config-$LABEL.dump" || exit 1

echo "Produced:"
ls -lh "$DUMP_DIR/knowledge-$LABEL.dump" "$DUMP_DIR/config-$LABEL.dump"
