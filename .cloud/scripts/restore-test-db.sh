# shellcheck shell=sh
# Restores the knowledge, config and codeclarity dumps into their _test databases.
# Usage: sh restore-test-db.sh (from .cloud/scripts)

for db in knowledge config codeclarity; do
	sh restore-db.sh "$db" "${db}_test" || exit 1
done
