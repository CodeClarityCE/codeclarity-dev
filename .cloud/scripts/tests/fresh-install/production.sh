#!/bin/sh
# Fresh-install test, production variant: on a Docker daemon with no codeclarity stack, runs
# the deployment Compose file with DOMAIN=localhost (`docker compose up -d` twice), creates a
# user with create-user, then checks what an operator and that user see after each run.
# Last, it sets a self-signed TLS_CERT and TLS_KEY and checks Caddy serves them, then unsets them.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/fresh-install/production.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule), WAIT_SECONDS (default 900),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see knowledge-dump-fixture.sh),
#      KNOWLEDGE_FIXTURE_CWE (a cwe_id the restored knowledge database must hold).
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
dir=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
WAIT_SECONDS=${WAIT_SECONDS:-900}
DOMAIN=localhost
export DOMAIN
URL="https://$DOMAIN"
EMAIL=operator@example.com
NAME="Fresh Install"
CREATE_USER_PASSWORD="fresh-install-$(date +%s)"
export CREATE_USER_PASSWORD
ANALYZER="Default Analyzer"
JOBS="generate-secrets knowledge-restore migrate default-analyzer"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

compose() {
	docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" "$@"
}

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
	for service in $JOBS db api frontend; do
		echo "--- logs: $service"
		compose logs --no-color --tail=100 "$service" || true
	done
}

# Prints "<service> <state> <exit code> <health>" for every container, one per line.
states() {
	compose ps -a --format json | jq -rs 'flatten | .[] | "\(.Service) \(.State) \(.ExitCode) \(.Health // "")"'
}

# Prints what keeps the stack from being settled: a job not exited 0, or a service not
# running and healthy (when it has a healthcheck). Prints nothing when it is settled.
unsettled() {
	states | while read -r service state code health; do
		case " $JOBS " in
		*" $service "*)
			if [ "$state" != exited ] || [ "$code" != 0 ]; then echo "$service $state $code"; fi
			;;
		*)
			if [ "$state" != running ] || { [ -n "$health" ] && [ "$health" != healthy ]; }; then
				echo "$service $state $health"
			fi
			;;
		esac
	done
}

restarts() {
	compose ps -aq | xargs docker inspect -f '{{.Name}} {{.RestartCount}}' | sort
}

# Waits for every job to succeed and every service to run, then checks nothing restarts
# for 30 seconds. Fails early if a job failed.
wait_settled() {
	deadline=$(($(date +%s) + WAIT_SECONDS))
	while :; do
		left=$(unsettled)
		[ -z "$left" ] && break
		if echo "$left" | grep -Eq "^($(echo "$JOBS" | tr ' ' '|')) exited [1-9]"; then
			echo "$left" >&2
			return 1
		fi
		[ "$(date +%s)" -lt "$deadline" ] || {
			echo "$left" >&2
			return 1
		}
		sleep 5
	done
	restarts >"$work/restarts.before"
	sleep 30
	restarts >"$work/restarts.after"
	[ -z "$(unsettled)" ] && cmp -s "$work/restarts.before" "$work/restarts.after"
}

sql() {
	# shellcheck disable=SC2016
	compose exec -T db sh -c '. /run/codeclarity/env && PGPASSWORD="$POSTGRES_PASSWORD" psql -XqtA -U postgres -d "$1" -c "$2"' sql "$1" "$2"
}

# Checksums of every generated secret and service view.
secrets_snapshot() {
	compose run --rm --no-deps -T --entrypoint sh generate-secrets -c \
		'cd /secrets && find . -type f ! -name "*.tmp" | LC_ALL=C sort | xargs sha256sum'
}

# Caddy's internal root certificate, which a DOMAIN=localhost instance serves from.
fetch_ca() {
	deadline=$(($(date +%s) + 120))
	until compose exec -T frontend cat /data/caddy/pki/authorities/local/root.crt >"$work/ca.crt" 2>/dev/null && [ -s "$work/ca.crt" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 2
	done
}

# Waits until $URL serves a certificate that verifies against the CA file $1.
wait_for_cert() {
	deadline=$(($(date +%s) + 120))
	until curl -fsS -o /dev/null --cacert "$1" "$URL/"; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 2
	done
}

# Prints a token for the created user, or nothing if login fails.
login() {
	curl -fsS --cacert "$work/ca.crt" -X POST "$URL/api/auth/authenticate" -H 'Content-Type: application/json' \
		-d "{\"email\":\"$EMAIL\",\"password\":\"$CREATE_USER_PASSWORD\"}" 2>/dev/null | jq -er '.data.token' 2>/dev/null || true
}

wait_for_login() {
	deadline=$(($(date +%s) + 300))
	token=$(login)
	while [ -z "$token" ] && [ "$(date +%s)" -lt "$deadline" ]; do
		sleep 5
		token=$(login)
	done
}

get() {
	curl -fsS --cacert "$work/ca.crt" "$URL/api$1" -H "Authorization: Bearer $token"
}

# Checks the stack after an `up -d`; $1 names the run.
check_stack() {
	for db in codeclarity knowledge plugins config; do
		result=ok
		want=$(find "$root/api/src/migrations/$db" -name '*.ts' | wc -l | tr -d ' ')
		got=$(sql "$db" "SELECT count(*) FROM migrations") || result=bad
		[ "$got" = "$want" ] || result=bad
		check "$1: $db has its $want migrations applied (has ${got:-none})" $result
	done

	if [ -n "${KNOWLEDGE_FIXTURE_CWE:-}" ]; then
		result=ok
		[ "$(sql knowledge "SELECT count(*) FROM cwe WHERE cwe_id = '$KNOWLEDGE_FIXTURE_CWE'")" = 1 ] || result=bad
		check "$1: knowledge holds the dump's $KNOWLEDGE_FIXTURE_CWE record once" $result
	fi

	result=ok
	[ "$(sql codeclarity "SELECT count(*) FROM pg_database WHERE datname LIKE '%\_test'")" = 0 ] || result=bad
	check "$1: there is no _test database" $result
}

# Checks what the created user sees through Caddy and the API; $1 names the run.
check_user() {
	wait_for_login
	if [ -z "$token" ]; then
		check "$1: $EMAIL logs in through $URL with no mail server" bad
		return
	fi
	check "$1: $EMAIL logs in through $URL with no mail server" ok

	result=ok
	org=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)] | if length == 1 then .[0].organization.id else error("personal orgs: \(length)") end') || result=bad
	check "$1: the user owns one personal organization" $result

	result=ok
	count=$(get "/org/$org/analyzers?page=0&entries_per_page=100" | jq --arg name "$ANALYZER" '[.data[] | select(.name == $name)] | length') || result=bad
	[ "$count" = 1 ] || result=bad
	check "$1: the user sees \"$ANALYZER\" once (saw ${count:-none})" $result

	result=ok
	[ "$(sql codeclarity 'SELECT count(*) FROM "user"')" = 1 ] || result=bad
	[ "$(sql codeclarity 'SELECT count(*) FROM organization')" = 1 ] || result=bad
	check "$1: the instance has exactly one user and one organization" $result
}

if [ -n "$(compose ps -aq)" ]; then
	echo "fresh-install: a codeclarity stack already exists on this daemon; this test needs an empty one" >&2
	exit 1
fi

result=ok
compose up -d || result=bad
check "first up -d succeeds" $result
result=ok
wait_settled || result=bad
check "first up -d: every job succeeds and every service runs, healthy where it has a healthcheck" $result
check_stack "first up -d"
secrets_snapshot >"$work/secrets.first" || true

result=ok
[ "$(sql codeclarity 'SELECT count(*) FROM "user"')" = 0 ] || result=bad
check "first up -d: the instance has no accounts" $result

result=ok
compose run --rm -T -e CREATE_USER_PASSWORD api create-user --email "$EMAIL" --name "$NAME" || result=bad
check "create-user succeeds" $result
result=ok
fetch_ca || result=bad
check "Caddy serves $DOMAIN from its internal CA" $result
check_user "after create-user"

result=ok
compose up -d || result=bad
check "second up -d succeeds" $result
result=ok
wait_settled || result=bad
check "second up -d: every job succeeds and every service runs" $result
check_stack "second up -d"
check_user "second up -d"

result=ok
compose logs --no-color knowledge-restore | grep -q 'nothing to restore' || result=bad
check "second up -d: the knowledge restore finds its work done" $result

result=ok
secrets_snapshot >"$work/secrets.second" || result=bad
[ -s "$work/secrets.first" ] || result=bad
cmp -s "$work/secrets.first" "$work/secrets.second" || result=bad
check "second up -d: no secret is generated or changed" $result

# An operator's own certificate, set in the environment as it would be in .env.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN="$DOMAIN" \
	-addext "subjectAltName=DNS:$DOMAIN" -keyout "$work/supplied.key" -out "$work/supplied.crt" 2>/dev/null
TLS_CERT=$(cat "$work/supplied.crt")
TLS_KEY=$(cat "$work/supplied.key")
export TLS_CERT TLS_KEY
result=ok
compose up -d || result=bad
wait_for_cert "$work/supplied.crt" || result=bad
check "with TLS_CERT and TLS_KEY set, Caddy serves the supplied certificate" $result

unset TLS_CERT TLS_KEY
result=ok
compose up -d || result=bad
wait_for_cert "$work/ca.crt" || result=bad
check "with TLS_CERT and TLS_KEY unset again, Caddy serves $DOMAIN from its internal CA" $result

if [ "$failed" -gt 0 ]; then
	report
fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
