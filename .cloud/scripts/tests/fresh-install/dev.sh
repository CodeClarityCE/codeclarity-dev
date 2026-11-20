#!/bin/sh
# Fresh-install test, dev variant: on a Docker daemon with no codeclarity-dev stack, runs
# `make up` twice, then checks what a developer sees through the API after each run, and
# runs the Default Analyzer on a tiny uploaded npm project after the first.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/fresh-install/dev.sh
# Env: API_URL (default http://localhost:3000), API_WAIT_SECONDS (default 900),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see knowledge-dump-fixture.sh),
#      KNOWLEDGE_FIXTURE_CWE (a cwe_id the restored knowledge database must hold),
#      ANALYSIS_WAIT_SECONDS (default 1200).
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
API_BASE=${API_URL:-http://localhost:3000}
LOGIN_WAIT_SECONDS=${API_WAIT_SECONDS:-900}
EMAIL=john.doe@codeclarity.io
LOGIN_EMAIL=$EMAIL
LOGIN_PASSWORD='ThisIs4Str0ngP4ssW0rd?'
CURL_CA=
ANALYZER="Default Analyzer"
JOBS="knowledge-restore test-databases migrate migrate-test dev-user default-analyzer vulnerability-instance-backfill"
ANALYSIS_SERVICES="service-dispatcher service-downloader service-package-follower plugin-js-sbom plugin-php-sbom plugin-vuln-finder plugin-license-finder api"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

COMPOSE_ROOT=$root
export COMPOSE_ROOT
cd "$root/.cloud/scripts" || exit 1
# shellcheck disable=SC1091
. ./compose.sh
# shellcheck source=lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"
cd "$root" || exit 1

# Checks what a developer sees after a `make up`; $1 names the run.
check_stack() {
	wait_for_login
	if [ -z "$token" ]; then
		check "$1: $EMAIL logs in through the API" bad
		return
	fi
	check "$1: $EMAIL logs in through the API" ok

	result=ok
	org=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)] | if length == 1 then .[0].organization.id else error("personal orgs: \(length)") end') || result=bad
	check "$1: the account owns one personal organization" $result

	result=ok
	count=$(get "/org/$org/analyzers?page=0&entries_per_page=100" | jq --arg name "$ANALYZER" '[.data[] | select(.name == $name)] | length') || result=bad
	[ "$count" = 1 ] || result=bad
	check "$1: the account sees \"$ANALYZER\" once (saw ${count:-none})" $result

	result=ok
	[ "$(sql codeclarity "SELECT count(*) FROM \"user\" WHERE email = '$EMAIL'")" = 1 ] || result=bad
	check "$1: there is exactly one $EMAIL user" $result

	for db in codeclarity knowledge config; do
		result=ok
		want=$(find "$root/api/src/migrations/$db" -name '*.ts' | wc -l | tr -d ' ')
		got=$(sql "$db" "SELECT count(*) FROM migrations") || result=bad
		[ "$got" = "$want" ] || result=bad
		check "$1: $db has its $want migrations applied (has ${got:-none})" $result
		result=ok
		got=$(sql "${db}_test" "SELECT count(*) FROM migrations") || result=bad
		[ "$got" = "$want" ] || result=bad
		check "$1: ${db}_test has its $want migrations applied (has ${got:-none})" $result
	done

	if [ -n "${KNOWLEDGE_FIXTURE_CWE:-}" ]; then
		result=ok
		[ "$(sql knowledge "SELECT count(*) FROM cwe WHERE cwe_id = '$KNOWLEDGE_FIXTURE_CWE'")" = 1 ] || result=bad
		check "$1: knowledge holds the dump's $KNOWLEDGE_FIXTURE_CWE record once" $result
	fi
}

if [ -n "$(compose ps -aq)" ]; then
	echo "fresh-install: a codeclarity-dev stack already exists on this daemon; this test needs an empty one" >&2
	exit 1
fi

for run in first second; do
	result=ok
	make up || { result=bad; report_unsettled; }
	check "$run make up succeeds" $result
	[ "$result" = ok ] || continue
	check_stack "$run make up"
	if [ "$run" = first ] && [ -n "${org:-}" ]; then check_analysis "$run make up" "$org"; fi
done

result=ok
compose logs --no-color knowledge-restore | grep -q 'nothing to restore' || result=bad
check "second make up: the knowledge restore finds its work done" $result

if [ "$failed" -gt 0 ]; then
	# shellcheck disable=SC2086 # a list of service names
	report $JOBS api
fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
