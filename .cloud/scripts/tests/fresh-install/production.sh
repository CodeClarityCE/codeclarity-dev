#!/bin/sh
# Fresh-install test of the deployment Compose file on an empty Docker daemon (CI only; it removes nothing),
# including the support bundle's secret redaction on the running instance.
# Usage: sh .cloud/scripts/tests/fresh-install/production.sh
# Env: DEPLOYMENT_DIR, WAIT_SECONDS (900), ANALYSIS_WAIT_SECONDS (1200), KNOWLEDGE_DUMP_IMAGE,
#      KNOWLEDGE_FIXTURE_CWE, UPGRADE_FROM (a release tag or "latest"; installs it first, needs gh).
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
JOBS=$PRODUCTION_JOBS
# A settled stack must then run 30 seconds without a restart.
SETTLE_SECONDS=30

# Checksums of every generated secret and service view.
secrets_snapshot() {
	compose run --rm --no-deps -T --entrypoint sh generate-secrets -c \
		'cd /secrets && find . -type f ! -name "*.tmp" | LC_ALL=C sort | xargs sha256sum'
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

# Checks app paths get the index page, real files keep their type, and /assets and /api keep their 404; $1 names the run.
check_deep_links() {
	for path in /tickets/integrations/clickup/callback /tickets /datasets /experiments /terms /privacy /projects/1 /no-such-page; do
		result=ok
		got=$(curl -sS --cacert "$CURL_CA" -o "$work/page.html" -w '%{http_code} %{content_type}' "$URL$path") || result=bad
		case $got in "200 text/html"*) ;; *) result=bad ;; esac
		grep -q '<title>CodeClarity</title>' "$work/page.html" || result=bad
		check "$1: $path serves the app's index page (got ${got:-nothing})" $result
	done

	result=ok
	got=$(curl -sS --cacert "$CURL_CA" -o /dev/null -w '%{http_code} %{content_type}' "$URL/favicon.ico") || result=bad
	case $got in "200 image/"*) ;; *) result=bad ;; esac
	check "$1: /favicon.ico is served as an image (got ${got:-nothing})" $result

	result=ok
	chunk=$(curl -fsS --cacert "$CURL_CA" "$URL/" | grep -o '/assets/[^"]*\.js' | head -n 1) || result=bad
	got=$(curl -sS --cacert "$CURL_CA" -o /dev/null -w '%{http_code} %{content_type}' "$URL${chunk:-/assets/none.js}") || result=bad
	case $got in "200 text/javascript"* | "200 application/javascript"*) ;; *) result=bad ;; esac
	check "$1: the built chunk ${chunk:-none} is served as JavaScript (got ${got:-nothing})" $result

	for path in /assets/does-not-exist.js /api/no-such-route; do
		result=ok
		got=$(curl -sS --cacert "$CURL_CA" -o "$work/page.html" -w '%{http_code}' "$URL$path") || result=bad
		[ "$got" = 404 ] || result=bad
		grep -q '<title>CodeClarity</title>' "$work/page.html" && result=bad
		check "$1: $path returns 404, not the index page (got ${got:-nothing})" $result
	done
}

# Checks the API's public URLs start with $URL; $1 names the run.
check_public_urls() {
	for pair in "WEB_HOST $URL" "HOST $URL/api"; do
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

# Whether the running API reports analyzer availability in org $1; released images may predate it.
api_reports_availability() {
	get "/org/$1/analyzers?page=0&entries_per_page=100" | jq -e '[.data[] | has("availability")] | any' >/dev/null 2>&1
}

# With CodeQL off (no codeql profile), checks an analyzer using it is unavailable and refused
# in org $2 on project $3; $1 names the run.
check_codeql_off() {
	result=ok
	! compose ps -a --format '{{.Service}}' | grep -qx plugin-codeql || result=bad
	check "$1: no CodeQL container runs without the codeql profile" $result

	if ! api_reports_availability "$2"; then
		echo "::notice::$1: the API image does not report analyzer availability, so the CodeQL refusal checks are skipped"
		return 0
	fi

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

# The default plugin the plugin-down check stops, and the first dispatcher release that fails its steps.
DOWN_PLUGIN=license-finder
STALLED_SINCE=v0.0.22-alpha

# Prints the state of "$ANALYZER" in org $1 as "<state> <plugins>".
analyzer_state() {
	get "/org/$1/analyzers?page=0&entries_per_page=100" |
		jq -r --arg n "$ANALYZER" '[.data[] | select(.name == $n)][0].availability | "\(.state) \((.plugins // []) | join(","))"'
}

# Waits up to 60 s until analyzer_state of org $1 is $2.
wait_analyzer_state() {
	deadline=$(($(date +%s) + 60))
	until [ "$(analyzer_state "$1" 2>/dev/null)" = "$2" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 3
	done
}

# Prints the analysis body of check_analysis for the Default Analyzer in org $1, project $2.
default_analysis_body() {
	id=$(get "/org/$1/analyzers?page=0&entries_per_page=100" | jq -er --arg n "$ANALYZER" '[.data[] | select(.name == $n)][0].id') || return 1
	path="$1/projects/$2/main"
	echo '{"analyzer_id":"'"$id"'","branch":"main","config":{"js-sbom":{"branch":"main","project":"'"$path"'"},"php-sbom":{"branch":"main","project":"'"$path"'"},"vuln-finder":{"vulnerabilityPolicy":[]},"license-finder":{"licensePolicy":[]}}}'
}

# Whether the running dispatcher image is at least $STALLED_SINCE, read from its config.json.
dispatcher_fails_stalled_steps() {
	image=$(compose config --format json | jq -er '.services["service-dispatcher"].image') || return 1
	version=$(docker run --rm --entrypoint cat "$image" config.json 2>/dev/null | jq -er .version) || return 1
	[ "$(printf '%s\n%s\n' "$STALLED_SINCE" "$version" | sort -V | head -n 1)" = "$STALLED_SINCE" ]
}

# Stops $DOWN_PLUGIN and checks "$ANALYZER" is temporarily down and refused in org $2 on project $3,
# then that a step already sent to the stopped plugin fails within a short grace delay; $1 names the run.
check_plugin_down() {
	if ! api_reports_availability "$2"; then
		echo "::notice::$1: the API image does not report analyzer availability, so the plugin-down checks in the API are skipped"
	else
		compose stop -t 0 "plugin-$DOWN_PLUGIN" >/dev/null 2>&1 || :
		result=ok
		wait_analyzer_state "$2" "down $DOWN_PLUGIN" || result=bad
		check "$1: with $DOWN_PLUGIN stopped, \"$ANALYZER\" is temporarily down, naming it (got $(analyzer_state "$2" 2>/dev/null || :))" $result

		before=$(sql codeclarity 'SELECT count(*) FROM analysis') || before=
		result=ok
		body=$(default_analysis_body "$2" "$3") || result=bad
		status=$(api_curl -sS -o "$work/down-refusal.json" -w '%{http_code}' -X POST "$API_BASE/org/$2/projects/$3/analyses" \
			-H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body") || result=bad
		[ "$status" = 409 ] || result=bad
		jq -e --arg p "$DOWN_PLUGIN" '.error_code == "AnalyzerUnavailable" and (.error_message | contains($p))' "$work/down-refusal.json" >/dev/null || result=bad
		after=$(sql codeclarity 'SELECT count(*) FROM analysis') || after=
		[ -n "$before" ] && [ "$before" = "$after" ] || result=bad
		check "$1: starting \"$ANALYZER\" while $DOWN_PLUGIN is down is refused and nothing is saved (HTTP ${status:-none})" $result

		compose start "plugin-$DOWN_PLUGIN" >/dev/null 2>&1 || :
		result=ok
		wait_analyzer_state "$2" "available " || result=bad
		check "$1: \"$ANALYZER\" is available again once $DOWN_PLUGIN restarts" $result
	fi

	if ! dispatcher_fails_stalled_steps; then
		echo "::notice::$1: the dispatcher image predates $STALLED_SINCE, so the stalled-step check is skipped"
		return 0
	fi
	# A short grace delay and reaper interval, for this check only.
	printf 'services:\n  service-dispatcher:\n    environment:\n      STALLED_PLUGIN_GRACE: "20"\n      REAPER_INTERVAL: "5"\n' >"$work/stalled.yaml"
	docker compose --project-directory "$cdir" -f "$cdir/docker-compose.yaml" -f "$work/stalled.yaml" up -d service-dispatcher >/dev/null 2>&1 || :
	wait_settled || report_unsettled

	result=ok
	body=$(default_analysis_body "$2" "$3") || result=bad
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	# Paused, the plugin keeps its consumer, so the API accepts the analysis, but cannot run the step.
	compose pause "plugin-$DOWN_PLUGIN" >/dev/null 2>&1 || result=bad
	analysis=$(post "/org/$2/projects/$3/analyses" "$body" | jq -er '.id') || result=bad
	# Stopped, its unacknowledged step goes back to a queue nothing consumes.
	compose stop -t 0 "plugin-$DOWN_PLUGIN" >/dev/null 2>&1 || :
	[ "$(compose ps -a --format '{{.State}}' "plugin-$DOWN_PLUGIN" 2>/dev/null)" = exited ] || result=bad
	deadline=$(($(date +%s) + 300))
	status=
	while [ "$result" = ok ]; do
		get "/org/$2/projects/$3/analyses/$analysis" >"$work/stalled.json" 2>/dev/null || :
		status=$(jq -r '.data.status // empty' "$work/stalled.json" 2>/dev/null) || status=
		case "$status" in completed | failure | cancelled) break ;; esac
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep 5
	done
	[ "$status" = failure ] || result=bad
	jq -e --arg p "$DOWN_PLUGIN" '.data.failure_reason | contains($p)' "$work/stalled.json" >/dev/null 2>&1 || result=bad
	check "$1: a step sent to a stopped $DOWN_PLUGIN fails the analysis within the grace delay, naming it (status ${status:-none})" $result
	if [ "$result" != ok ]; then
		jq '.data | {status, failure_reason, steps}' "$work/stalled.json" 2>/dev/null || :
		compose logs --no-color --timestamps --since "$since" service-dispatcher "plugin-$DOWN_PLUGIN" 2>/dev/null || :
	fi

	compose start "plugin-$DOWN_PLUGIN" >/dev/null 2>&1 || :
	compose up -d service-dispatcher >/dev/null 2>&1 || :
	wait_settled || report_unsettled
}

MONITORING_SERVICES="prometheus grafana postgres_exporter"

# Checks no monitoring container exists and Caddy's monitoring routes answer 503 with a
# message naming the profile; $1 names the run.
check_monitoring_off() {
	for service in $MONITORING_SERVICES; do
		result=ok
		[ -z "$(docker ps -aq --filter "label=com.docker.compose.service=$service")" ] || result=bad
		check "$1: no $service container exists while monitoring is off" $result
	done
	result=ok
	code=$(curl -sS --cacert "$work/ca.crt" -o "$work/monitoring.body" -w '%{http_code}' "https://$DOMAIN:3001/") || result=bad
	[ "$code" = 503 ] || result=bad
	grep -q 'monitoring' "$work/monitoring.body" || result=bad
	check "$1: https://$DOMAIN:3001 answers 503 naming the monitoring profile (got ${code:-nothing})" $result
	result=ok
	# Port 9091 is not published, so ask Caddy from inside its container; busybox wget prints only the status.
	compose exec -T frontend wget -qO /dev/null --no-check-certificate "https://$DOMAIN:9091/" >"$work/monitoring.body" 2>&1 && result=bad
	grep -q ' 503' "$work/monitoring.body" || result=bad
	check "$1: Caddy's Prometheus route answers 503" $result
}

# Prints how many series of the PromQL query $1 Prometheus returns.
prom_count() {
	compose exec -T prometheus wget -qO- "http://localhost:9090/api/v1/query?query=$1" | jq -er '.data.result | length'
}

# Checks Prometheus scrapes the stack and Grafana, through Caddy, reads from Prometheus; $1 names the run.
check_monitoring_on() {
	deadline=$(($(date +%s) + 180))
	until [ "$(prom_count 'up%7Bjob%3D%22rabbitmq%22%7D%3D%3D1' 2>/dev/null)" = 1 ] &&
		[ "$(prom_count 'up%7Bjob%3D%22postgres%22%7D%3D%3D1' 2>/dev/null)" = 1 ]; do
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep 5
	done
	for job in rabbitmq postgres; do
		result=ok
		[ "$(prom_count "up%7Bjob%3D%22$job%22%7D%3D%3D1" 2>/dev/null)" = 1 ] || result=bad
		check "$1: Prometheus scrapes the $job target" $result
	done

	result=ok
	curl -fsS --cacert "$work/ca.crt" "https://$DOMAIN:3001/api/health" | jq -e '.database == "ok"' >/dev/null || result=bad
	check "$1: Grafana answers through Caddy at https://$DOMAIN:3001" $result

	result=ok
	password=$(compose run --rm --no-deps -T --entrypoint cat grafana /run/codeclarity/admin_password) || result=bad
	frames=$(curl -fsS --cacert "$work/ca.crt" -u "admin:$password" -X POST "https://$DOMAIN:3001/api/ds/query" \
		-H 'Content-Type: application/json' \
		-d '{"from":"now-5m","to":"now","queries":[{"refId":"A","datasource":{"uid":"prometheus"},"expr":"up","instant":true}]}' |
		jq -er '.results.A.frames | length') || result=bad
	[ "${frames:-0}" -gt 0 ] || result=bad
	check "$1: Grafana's Prometheus data source returns data" $result
}

# Prints every secret value the instance holds, one per line: the secrets store, without
# certificates, public keys, the salt or PEM armour lines.
known_secrets() {
	compose run --rm --no-deps -T --entrypoint sh generate-secrets -c \
		'find /secrets/.store -type f ! -name "*.crt" ! -name "*public*" ! -name "*_salt" ! -name "*.tmp" -exec cat {} +' |
		grep -v '^-----' | awk 'length($0) >= 8'
}

# Runs `make support-bundle` with a TLS key and made-up settings secrets in the environment, then
# checks it holds versions, config, error logs and a fresh error report, and no secret value; $1 names the run.
check_support_bundle() {
	wait_for_login
	marker="support bundle check $(date +%s)"
	result=ok
	post /logs '{"level":"error","msg":"'"$marker"'","fields":{"route":"/fresh-install"}}' >/dev/null || result=bad
	check "$1: the web app's error report endpoint accepts a report" $result

	mail="mail-password-$(date +%s)-x" clickup="clickup-secret-$(date +%s)-y" nvd="nvd-key-$(date +%s)-z"
	result=ok
	mkdir -p "$work/bundle"
	MAIL_AUTH_PASSWORD=$mail CLICKUP_CLIENT_SECRET=$clickup NVD_API_KEY=$nvd \
		make --no-print-directory -C "$cdir" support-bundle OUT="$work/bundle" >"$work/bundle.out" 2>"$work/bundle.err" || result=bad
	archive=$(tail -n 1 "$work/bundle.out")
	case $archive in "$work/bundle/codeclarity-support-"*.tar.gz) [ -f "$archive" ] || result=bad ;; *) result=bad ;; esac
	check "$1: make support-bundle writes an archive and prints its path (${archive:-nothing})" $result
	if [ "$result" != ok ]; then
		cat "$work/bundle.out" "$work/bundle.err"
		return 0
	fi

	rm -rf "$work/bundle.x"
	mkdir -p "$work/bundle.x"
	tar -xzf "$archive" -C "$work/bundle.x"
	result=ok
	grep -q "$CODECLARITY_VERSION" "$work"/bundle.x/*/versions.txt || result=bad
	grep -q 'codeclarityce/api' "$work"/bundle.x/*/versions.txt || result=bad
	grep -q 'pgbouncer' "$work"/bundle.x/*/config.yaml || result=bad
	[ -n "$(find "$work"/bundle.x/*/logs -name '*.log')" ] || result=bad
	grep -qF "$marker" "$work"/bundle.x/*/error-reports.log || result=bad
	check "$1: the bundle holds versions, config, service logs and the new error report" $result

	result=ok
	{
		known_secrets || result=bad
		printf '%s\n' "$CREATE_USER_PASSWORD" "$mail" "$clickup" "$nvd"
		printf '%s\n' "$TLS_KEY" | grep -v '^-----'
	} >"$work/secrets.known"
	[ "$(wc -l <"$work/secrets.known")" -gt 10 ] || result=bad
	find "$work/bundle.x" -type f -exec cat {} + >"$work/bundle.all"
	while IFS= read -r secret; do
		[ -n "$secret" ] || continue
		if grep -qF -- "$secret" "$work/bundle.all"; then
			result=bad
			echo "a known secret is in the bundle, in: $(grep -rlF -- "$secret" "$work/bundle.x" | sed "s#$work/bundle.x/##" | tr '\n' ' ')"
		fi
	done <"$work/secrets.known"
	check "$1: no known secret value is in the bundle ($(wc -l <"$work/secrets.known") values checked)" $result
	rm -f "$work/secrets.known"
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
check_deep_links "after create-user"
if [ -n "${org:-}" ]; then check_analysis "after create-user" "$org"; fi
# An upgraded instance keeps the previous release's monitoring and CodeQL containers until removed.
if [ -z "$UPGRADE_FROM" ]; then check_monitoring_off "first up -d"; fi
if [ -z "$UPGRADE_FROM" ] && [ -n "${org:-}" ] && [ -n "${project:-}" ]; then
	check_codeql_off "after create-user" "$org" "$project"
	check_plugin_down "after create-user" "$org" "$project"
fi

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
check_support_bundle "with TLS_CERT and TLS_KEY set"

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

# The monitoring profile, as an operator would turn it on in .env.
COMPOSE_PROFILES=monitoring
export COMPOSE_PROFILES
result=ok
compose up -d || { result=bad; report_unsettled; }
wait_settled || { result=bad; report_unsettled; }
check "with COMPOSE_PROFILES=monitoring: up -d succeeds and every service runs" $result
check_monitoring_on "with COMPOSE_PROFILES=monitoring"
check_user "with COMPOSE_PROFILES=monitoring"

if [ "$failed" -gt 0 ]; then
	# shellcheck disable=SC2086 # a list of service names
	report $JOBS db api frontend $MONITORING_SERVICES
fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
