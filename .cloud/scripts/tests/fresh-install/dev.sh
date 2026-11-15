#!/bin/sh
# Fresh-install test, dev variant: on a Docker daemon with no codeclarity-dev stack, runs
# `make up` twice, then checks what a developer sees through the API after each run.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/fresh-install/dev.sh
# Env: API_URL (default http://localhost:3000), API_WAIT_SECONDS (default 900),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see knowledge-dump-fixture.sh),
#      KNOWLEDGE_FIXTURE_CWE (a cwe_id the restored knowledge database must hold).
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
API_URL=${API_URL:-http://localhost:3000}
API_WAIT_SECONDS=${API_WAIT_SECONDS:-900}
EMAIL=john.doe@codeclarity.io
PASSWORD='ThisIs4Str0ngP4ssW0rd?'
ANALYZER="Default Analyzer"

COMPOSE_ROOT=$root
export COMPOSE_ROOT
cd "$root/.cloud/scripts" || exit 1
# shellcheck disable=SC1091
. ./compose.sh
cd "$root" || exit 1

passed=0 failed=0

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
	fi
}

# Prints the stack state and the setup jobs' logs, for a failed run.
report() {
	compose ps -a || true
	for job in knowledge-restore test-databases migrate migrate-test dev-user default-analyzer; do
		echo "--- logs: $job"
		compose logs --no-color --tail=100 "$job" || true
	done
	echo "--- logs: api"
	compose logs --no-color --tail=100 api || true
}

sql() {
	compose exec -T db psql -XqtA -U postgres -d "$1" -c "$2"
}

# Prints a token for the default developer account, or nothing if login fails.
login() {
	curl -fsS -X POST "$API_URL/auth/authenticate" -H 'Content-Type: application/json' \
		-d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" 2>/dev/null | jq -er '.data.token' 2>/dev/null || true
}

# Waits for the API to accept the default developer account, then sets token.
wait_for_login() {
	deadline=$(($(date +%s) + API_WAIT_SECONDS))
	token=$(login)
	while [ -z "$token" ] && [ "$(date +%s)" -lt "$deadline" ]; do
		sleep 5
		token=$(login)
	done
}

get() {
	curl -fsS "$API_URL$1" -H "Authorization: Bearer $token"
}

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
	make up || result=bad
	check "$run make up succeeds" $result
	[ "$result" = ok ] && check_stack "$run make up"
done

result=ok
compose logs --no-color knowledge-restore | grep -q 'nothing to restore' || result=bad
check "second make up: the knowledge restore finds its work done" $result

if [ "$failed" -gt 0 ]; then
	report
fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
