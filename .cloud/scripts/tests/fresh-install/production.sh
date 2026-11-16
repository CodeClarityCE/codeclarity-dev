#!/bin/sh
# Fresh-install test, production variant: on a Docker daemon with no codeclarity stack, runs
# the deployment Compose file with DOMAIN=localhost (`docker compose up -d` twice), creates a
# user with create-user, then checks what an operator and that user see after each run, and
# runs the Default Analyzer on a tiny uploaded npm project as that user.
# With UPGRADE_FROM, it first installs a previous deployment release from its release assets
# and creates the user there, so the first `up -d` is the upgrade: the version is bumped,
# and the user and its data must be kept and the new migrations applied.
# Then it sets a self-signed TLS_CERT and TLS_KEY and checks Caddy serves them, then unsets them.
# With the codeql profile off, it checks no CodeQL container runs, an analyzer using CodeQL is
# unavailable and names CodeQL, and the API refuses to start it, saving nothing.
# Last, it publishes HTTP and HTTPS on 8080 and 8443 and checks logins, the HTTP redirect and the
# API's public URLs use that port, then puts the ports back.
# It never removes anything, so run it on a throwaway daemon (CI) only.
#
# Usage: sh .cloud/scripts/tests/fresh-install/production.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule), WAIT_SECONDS (default 900),
#      KNOWLEDGE_DUMP_IMAGE (passed to Compose; see knowledge-dump-fixture.sh),
#      KNOWLEDGE_FIXTURE_CWE (a cwe_id the restored knowledge database must hold),
#      UPGRADE_FROM (a deployment release tag, or "latest" for the newest release with a
#      Compose file; needs gh. It skips the test when there is no such release),
#      ANALYSIS_WAIT_SECONDS (default 1200).
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
JOBS="version-check generate-secrets knowledge-restore migrate default-analyzer"
DEPLOYMENT_REPO=CodeClarityCE/deployment
UPGRADE_FROM=${UPGRADE_FROM:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
WORK=$work
API_BASE="$URL/api"
CURL_CA="$work/ca.crt"
LOGIN_EMAIL=$EMAIL
LOGIN_PASSWORD=$CREATE_USER_PASSWORD
LOGIN_WAIT_SECONDS=300
ANALYSIS_SERVICES="service-dispatcher service-downloader service-follower plugin-js-sbom plugin-php-sbom plugin-vuln-finder plugin-license-finder api"
# The version the stack runs; the previous release's own .env sets it while that one runs.
unset CODECLARITY_VERSION
# The Compose project directory in use: the previous release's, then this checkout's.
cdir=$dir

compose() {
	docker compose --project-directory "$cdir" -f "$cdir/docker-compose.yaml" "$@"
}

# shellcheck source=lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"

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

# Checks that http://$DOMAIN$1 redirects to $URL, keeping the path and query; $2 names the run.
check_redirect() {
	result=ok
	location=$(curl -sS -o /dev/null -w '%{redirect_url}' "http://$DOMAIN$1/projects?page=1") || result=bad
	[ "$location" = "$URL/projects?page=1" ] || result=bad
	check "$2: http://$DOMAIN$1 redirects to $URL (got ${location:-nothing})" $result
}

# Checks the API's public URLs start with $URL; $1 names the run.
check_public_urls() {
	for pair in "WEB_HOST $URL" "GITHUB_AUTH_CALLBACK $URL/auth/github/callback" "GITLAB_AUTH_CALLBACK $URL/auth/gitlab/callback"; do
		var=${pair%% *}
		result=ok
		got=$(compose exec -T api printenv "$var") || result=bad
		[ "$got" = "${pair#* }" ] || result=bad
		check "$1: the API's $var is ${pair#* } (got ${got:-nothing})" $result
	done
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

# With CodeQL off (no codeql profile), checks an analyzer using it is unavailable and refused
# in org $2 on project $3; $1 names the run.
check_codeql_off() {
	result=ok
	! compose ps -a --format '{{.Service}}' | grep -qx plugin-codeql || result=bad
	check "$1: no CodeQL container runs without the codeql profile" $result

	result=ok
	get "/org/$2/analyzers?page=0&entries_per_page=100" >"$work/analyzers.json" || result=bad
	jq -e --arg name "$ANALYZER" '[.data[] | select(.name == $name)][0].availability.state == "available"' \
		"$work/analyzers.json" >/dev/null || result=bad
	check "$1: \"$ANALYZER\" is available with CodeQL off" $result

	step='{"version":"v1","config":{},"persistant_config":{}}'
	body='{"name":"CodeQL Analyzer","description":"Fresh install CodeQL check","steps":[['"$(echo "$step" | jq -c '.name = "js-sbom"')"','"$(echo "$step" | jq -c '.name = "codeql"')"']]}'
	result=ok
	codeql=$(post "/org/$2/analyzers" "$body" | jq -er '.id') || result=bad
	check "$1: an analyzer using CodeQL is created" $result
	[ "$result" = ok ] || return 0

	result=ok
	reason=$(get "/org/$2/analyzers/$codeql" | jq -er '.data.availability | select(.state == "off") | .message') || result=bad
	case "$reason" in *CodeQL*"off on this instance"*) ;; *) result=bad ;; esac
	check "$1: the CodeQL analyzer is unavailable, naming CodeQL (says ${reason:-nothing})" $result

	before=$(sql codeclarity 'SELECT count(*) FROM analysis') || before=
	result=ok
	status=$(api_curl -sS -o "$work/refusal.json" -w '%{http_code}' -X POST "$API_BASE/org/$2/projects/$3/analyses" \
		-H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
		-d '{"analyzer_id":"'"$codeql"'","branch":"main","config":{}}') || result=bad
	[ "$status" = 409 ] || result=bad
	jq -e --arg reason "$reason" '.error_code == "AnalyzerUnavailable" and .error_message == $reason' "$work/refusal.json" >/dev/null || result=bad
	after=$(sql codeclarity 'SELECT count(*) FROM analysis') || after=
	[ -n "$before" ] && [ "$before" = "$after" ] || result=bad
	check "$1: starting it is refused with the same reason and nothing is saved (HTTP ${status:-none})" $result
	[ "$result" = ok ] || cat "$work/refusal.json" 2>/dev/null || true
}

# Row counts of what an upgrade must keep.
kept_rows() {
	for table in '"user"' organization analyzer project analysis; do
		printf '%s %s\n' "$table" "$(sql codeclarity "SELECT count(*) FROM $table")"
	done
}

# Prints the newest deployment release that has a Compose file, or nothing.
latest_release() {
	gh api "repos/$DEPLOYMENT_REPO/releases?per_page=50" \
		--jq '[.[] | select(any(.assets[]; .name == "docker-compose.yaml"))][0].tag_name // empty'
}

# Installs the previous release from its assets and creates the user there.
install_previous() {
	prev="$work/previous"
	mkdir -p "$prev"
	gh release download "$UPGRADE_FROM" -R "$DEPLOYMENT_REPO" -D "$prev" -p docker-compose.yaml -p env.example
	cp "$prev/env.example" "$prev/.env"
	cdir=$prev
	result=ok
	compose up -d || { result=bad; report_unsettled; }
	check "previous release $UPGRADE_FROM: up -d succeeds" $result
	result=ok
	wait_settled || { result=bad; report_unsettled; }
	check "previous release $UPGRADE_FROM: every job succeeds and every service runs" $result
	result=ok
	compose run --rm -T -e CREATE_USER_PASSWORD api create-user --email "$EMAIL" --name "$NAME" || result=bad
	check "previous release $UPGRADE_FROM: create-user succeeds" $result
	kept_rows >"$work/rows.before" || true
	cdir=$dir
}

if [ -n "$(compose ps -aq)" ]; then
	echo "fresh-install: a codeclarity stack already exists on this daemon; this test needs an empty one" >&2
	exit 1
fi

if [ "$UPGRADE_FROM" = latest ]; then
	UPGRADE_FROM=$(latest_release)
	if [ -z "$UPGRADE_FROM" ]; then
		echo "skip: $DEPLOYMENT_REPO has no release with a docker-compose.yaml asset yet, so there is nothing to upgrade from"
		exit 0
	fi
fi
if [ -n "$UPGRADE_FROM" ]; then
	install_previous
fi

# The version this checkout's Compose file is released as; the upgrade bumps .env to it.
CODECLARITY_VERSION=$(jq -er .version "$dir/config.json")
export CODECLARITY_VERSION

result=ok
compose up -d || { result=bad; report_unsettled; }
check "first up -d succeeds" $result
result=ok
wait_settled || { result=bad; report_unsettled; }
check "first up -d: every job succeeds and every service runs, healthy where it has a healthcheck" $result
check_stack "first up -d"
secrets_snapshot >"$work/secrets.first" || true

if [ -n "$UPGRADE_FROM" ]; then
	result=ok
	kept_rows >"$work/rows.after" || result=bad
	[ -s "$work/rows.before" ] || result=bad
	cmp -s "$work/rows.before" "$work/rows.after" || result=bad
	check "upgrade from $UPGRADE_FROM keeps every user, organization, analyzer, project and analysis" $result
else
	result=ok
	[ "$(sql codeclarity 'SELECT count(*) FROM "user"')" = 0 ] || result=bad
	check "first up -d: the instance has no accounts" $result
fi

result=ok
compose run --rm -T -e CREATE_USER_PASSWORD api create-user --email "$EMAIL" --name "$NAME" || result=bad
check "create-user succeeds" $result
result=ok
fetch_ca || result=bad
check "Caddy serves $DOMAIN from its internal CA" $result
check_user "after create-user"
if [ -n "${org:-}" ]; then check_analysis "after create-user" "$org"; fi
if [ -n "${org:-}" ] && [ -n "${project:-}" ]; then check_codeql_off "after create-user" "$org" "$project"; fi

result=ok
compose up -d || { result=bad; report_unsettled; }
check "second up -d succeeds" $result
result=ok
wait_settled || { result=bad; report_unsettled; }
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
compose up -d || { result=bad; report_unsettled; }
wait_for_cert "$work/supplied.crt" || result=bad
check "with TLS_CERT and TLS_KEY set, Caddy serves the supplied certificate" $result

unset TLS_CERT TLS_KEY
result=ok
compose up -d || { result=bad; report_unsettled; }
wait_for_cert "$work/ca.crt" || result=bad
check "with TLS_CERT and TLS_KEY unset again, Caddy serves $DOMAIN from its internal CA" $result

# Other published ports, as when 80 and 443 are taken on the host.
HTTP_PORT=8080 HTTPS_PORT=8443 HTTP3_PORT=8443
export HTTP_PORT HTTPS_PORT HTTP3_PORT
URL="https://$DOMAIN:$HTTPS_PORT"
API_BASE="$URL/api"
result=ok
compose up -d || { result=bad; report_unsettled; }
wait_settled || { result=bad; report_unsettled; }
check "with HTTPS_PORT=$HTTPS_PORT: up -d succeeds and every service runs" $result
check_user "with HTTPS_PORT=$HTTPS_PORT"
check_redirect ":$HTTP_PORT" "with HTTPS_PORT=$HTTPS_PORT"
check_public_urls "with HTTPS_PORT=$HTTPS_PORT"

unset HTTP_PORT HTTPS_PORT HTTP3_PORT
URL="https://$DOMAIN"
API_BASE="$URL/api"
result=ok
compose up -d || { result=bad; report_unsettled; }
wait_settled || { result=bad; report_unsettled; }
check "with the ports unset again: up -d succeeds and every service runs" $result
check_user "with the ports unset again"
check_redirect "" "with the ports unset again"
check_public_urls "with the ports unset again"

if [ "$failed" -gt 0 ]; then
	# shellcheck disable=SC2086 # a list of service names
	report $JOBS db api frontend
fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
