#!/bin/sh
# The trimmed real stack the e2e journey runs against: the deployment Compose file with
# docker-compose.yaml from this folder merged over it, on the images build-images.sh built.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/real-stack/stack.sh up | knowledge-update | report | ca FILE | psql DB
#                                                   | offline SERVICE
#   up                starts the stack on an empty daemon, creates the dev account and waits until
#                     it logs in through Caddy at https://localhost
#   knowledge-update  runs one knowledge update in service-knowledge from the advisories in
#                     advisory-database/ (GHSA-w9mr-4mfr-499f of the dump plus GHSA-3fx5-fwvr-xrjg)
#   report            prints the stack state and the last logs of every service
#   ca                writes Caddy's internal root certificate to FILE, for curl --cacert
#   psql              runs the SQL on stdin in database DB as postgres, one line per row
#   offline           fails unless SERVICE's container is only on internal networks (no outbound access)
# Env: DEPLOYMENT_DIR (default: the deployment submodule), WAIT_SECONDS (default 600),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see ../fresh-install/knowledge-dump-fixture.sh),
#      STACK_OVERRIDE (a further Compose file merged last, such as the results gate's).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
dir=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
WAIT_SECONDS=${WAIT_SECONDS:-600}
DOMAIN=localhost
export DOMAIN
# The dev account, as on the dev stack.
LOGIN_EMAIL=john.doe@codeclarity.io
LOGIN_PASSWORD='ThisIs4Str0ngP4ssW0rd?'
API_BASE="https://$DOMAIN/api"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CURL_CA="$WORK/ca.crt"

compose() {
	if [ -n "${STACK_OVERRIDE:-}" ]; then set -- -f "$STACK_OVERRIDE" "$@"; fi
	docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" -f "$here/docker-compose.yaml" "$@"
}

# shellcheck source=../fresh-install/lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"
JOBS=$PRODUCTION_JOBS

up() {
	if [ -n "$(compose ps -aq)" ]; then
		echo "real-stack: a codeclarity stack already exists on this daemon; this needs an empty one" >&2
		exit 1
	fi
	start=$(date +%s)
	compose up -d || {
		report_unsettled
		exit 1
	}
	CREATE_USER_PASSWORD=$LOGIN_PASSWORD compose run --rm -T -e CREATE_USER_PASSWORD api \
		create-user --email "$LOGIN_EMAIL" --name "John Doe" || {
		report_unsettled
		exit 1
	}
	wait_settled || {
		report_unsettled
		exit 1
	}
	fetch_ca || {
		echo "real-stack: Caddy served no internal CA certificate" >&2
		report frontend
		exit 1
	}
	LOGIN_WAIT_SECONDS=$WAIT_SECONDS
	wait_for_login
	if [ -z "$token" ]; then
		echo "real-stack: $LOGIN_EMAIL could not log in through $API_BASE" >&2
		report api frontend
		exit 1
	fi
	echo "real-stack: ready in $(($(date +%s) - start))s; $LOGIN_EMAIL logs in through $API_BASE"
}

# The OSV advisories of a github/advisory-database checkout replace the knowledge's, as an
# update from upstream would, without reaching the network.
knowledge_update() {
	compose run --rm --no-deps -T -v "$here/advisory-database:/advisory-database:ro" service-knowledge \
		./plugin -knowledge -action update-asof -asof "$(date -u +%Y-%m-%d)" -advisory-repo /advisory-database || {
		echo "real-stack: the knowledge update failed" >&2
		exit 1
	}
	echo "real-stack: the knowledge holds the advisories of $here/advisory-database"
}

# Fails unless every network of service $1's container is internal, so it has no outbound access.
offline() {
	container=$(compose ps -q "$1")
	[ -n "$container" ] || {
		echo "real-stack: $1 is not running" >&2
		exit 1
	}
	networks=$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$container")
	[ -n "$networks" ] || {
		echo "real-stack: $1 is on no network" >&2
		exit 1
	}
	for network in $networks; do
		[ "$(docker network inspect -f '{{.Internal}}' "$network")" = true ] || {
			echo "real-stack: $1 is on network $network, which reaches outside the stack" >&2
			exit 1
		}
	done
	echo "real-stack: $1 is only on internal networks: $(echo "$networks" | tr '\n' ' ')"
}

case ${1:-} in
up) up ;;
knowledge-update) knowledge_update ;;
report)
	# shellcheck disable=SC2046 # one word per service
	report $(compose config --services)
	;;
ca)
	[ -n "${2:-}" ] || {
		echo "usage: stack.sh ca FILE" >&2
		exit 2
	}
	CURL_CA=$2
	fetch_ca
	;;
psql)
	[ -n "${2:-}" ] || {
		echo "usage: stack.sh psql DB" >&2
		exit 2
	}
	# shellcheck disable=SC2016 # expanded in the db container
	compose exec -T db sh -c 'if [ -f /run/codeclarity/env ]; then . /run/codeclarity/env; fi
		PGPASSWORD="$POSTGRES_PASSWORD" psql -X -q -t -A -v ON_ERROR_STOP=1 -U postgres -d "$1"' psql "$2"
	;;
offline)
	[ -n "${2:-}" ] || {
		echo "usage: stack.sh offline SERVICE" >&2
		exit 2
	}
	offline "$2"
	;;
*)
	echo "usage: stack.sh up | knowledge-update | report | ca FILE | psql DB | offline SERVICE" >&2
	exit 2
	;;
esac
