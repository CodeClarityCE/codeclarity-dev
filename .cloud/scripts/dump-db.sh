# shellcheck shell=sh
# Dumps one database to deployment/dump/<db>.dump. knowledge and config go through
# dump-knowledge.sh instead, so they are only dumped after the completeness gate passes.
case "$1" in
knowledge | config)
	echo "Error: dump $1 with make dump-knowledge, which runs the completeness gate first" >&2
	exit 1
	;;
esac

. ./compose.sh

compose exec db sh -c "PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d $1 -Fc > /dump/$1.dump"