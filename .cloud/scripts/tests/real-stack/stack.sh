#!/bin/sh
# The trimmed real stack the e2e journey runs against: the deployment Compose file with
# docker-compose.yaml from this folder merged over it, on the images build-images.sh built.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/real-stack/stack.sh up | report
#   up      starts the stack on an empty daemon, creates the dev account and waits until it
#           logs in through Caddy at https://localhost
#   report  prints the stack state and the last logs of every service
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
JOBS="version-check generate-secrets knowledge-restore migrate default-analyzer vulnerability-instance-backfill"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CURL_CA="$WORK/ca.crt"

compose() {
	docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" -f "$here/docker-compose.yaml" "$@"
}

# shellcheck source=../fresh-install/lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"

# Prints each container that is not settled yet: a job not exited 0, or a service not running.
unsettled() {
	compose ps -a --format json | jq -rs 'flatten | .[] | "\(.Service) \(.State) \(.ExitCode)"' |
		while read -r service state code; do
			case " $JOBS " in
			*" $service "*) if [ "$state" != exited ] || [ "$code" != 0 ]; then echo "$service $state $code"; fi ;;
			*) if [ "$state" != running ]; then echo "$service $state"; fi ;;
			esac
		done
}

# Waits for every job to succeed and every service to run; fails early when a job failed.
wait_settled() {
	deadline=$(($(date +%s) + WAIT_SECONDS))
	while left=$(unsettled) && [ -n "$left" ]; do
		if echo "$left" | grep -Eq "^($(echo "$JOBS" | tr ' ' '|')) exited [1-9]" || [ "$(date +%s)" -ge "$deadline" ]; then
			echo "$left" >&2
			return 1
		fi
		sleep 2
	done
}

# Copies Caddy's internal root certificate, which a DOMAIN=localhost instance serves from.
fetch_ca() {
	deadline=$(($(date +%s) + 120))
	until compose exec -T frontend cat /data/caddy/pki/authorities/local/root.crt >"$CURL_CA" 2>/dev/null && [ -s "$CURL_CA" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 2
	done
}

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

case ${1:-} in
up) up ;;
# shellcheck disable=SC2046 # one word per service
report) report $(compose config --services) ;;
*)
	echo "usage: stack.sh up | report" >&2
	exit 2
	;;
esac
