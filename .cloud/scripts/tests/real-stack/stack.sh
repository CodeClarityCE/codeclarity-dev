#!/bin/sh
# The trimmed real stack the e2e journey runs against: the deployment Compose file with
# docker-compose.yaml from this folder merged over it, on the images build-images.sh built.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/real-stack/stack.sh up | knowledge-update | report
#   up                starts the stack on an empty daemon, creates the dev account and waits until
#                     it logs in through Caddy at https://localhost
#   knowledge-update  runs one knowledge update in service-knowledge from the advisories in
#                     advisory-database/ (GHSA-w9mr-4mfr-499f of the dump plus GHSA-3fx5-fwvr-xrjg)
#   report            prints the stack state and the last logs of every service
# Env: DEPLOYMENT_DIR (default: the deployment submodule), WAIT_SECONDS (default 600),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see ../fresh-install/knowledge-dump-fixture.sh).
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

case ${1:-} in
up) up ;;
knowledge-update) knowledge_update ;;
report)
	# shellcheck disable=SC2046 # one word per service
	report $(compose config --services)
	;;
*)
	echo "usage: stack.sh up | knowledge-update | report" >&2
	exit 2
	;;
esac
