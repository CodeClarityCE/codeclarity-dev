# shellcheck shell=sh
# Helpers shared by the dev and production fresh-install tests and the accuracy benchmark.
# Source it after defining compose(), which report, report_unsettled and sql need.
# Settings, set by the caller:
#   API_BASE        the API's base URL (http://localhost:3000, or https://localhost/api)
#   CURL_CA         a CA file to verify API_BASE against, or empty
#   LOGIN_EMAIL, LOGIN_PASSWORD, LOGIN_WAIT_SECONDS   the account the checks log in as
#   WORK            a scratch directory
#   ANALYSIS_SERVICES   the services whose logs explain a failed analysis
#   ANALYSIS_WAIT_SECONDS (default 1200), ANALYSIS_POLL_SECONDS (default 10)
#   JOBS, WAIT_SECONDS   the one-shot setup jobs and how long wait_settled waits for them
#   SETTLE_SECONDS  how long wait_settled then checks that nothing restarts (default 0)

passed=0 failed=0

# The deployment Compose file's one-shot setup jobs.
# shellcheck disable=SC2034 # read by the scripts that source this file
PRODUCTION_JOBS="version-check generate-secrets knowledge-restore migrate default-analyzer vulnerability-instance-backfill"

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
	fi
}

# Prints the stack state and the last logs of each service named.
report() {
	compose ps -a || true
	for service; do
		echo "--- logs: $service"
		compose logs --no-color --tail=100 "$service" || true
	done
}

# Prints the logs of every service that is neither running (and healthy, if it has a check) nor exited 0.
report_unsettled() {
	compose ps -a || true
	compose ps -a --format '{{.Service}} {{.State}} {{.Health}} {{.ExitCode}}' 2>/dev/null |
		while read -r service state health code; do
			case "$state:$health:$code" in
			running:healthy:* | running::* | exited:*:0) ;;
			*)
				echo "--- logs: $service ($state $health exit $code)"
				compose logs --no-color --tail=80 "$service" || true
				;;
			esac
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
# for SETTLE_SECONDS. Fails early if a job failed.
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
	[ "${SETTLE_SECONDS:-0}" -gt 0 ] || return 0
	restarts >"$WORK/restarts.before"
	sleep "$SETTLE_SECONDS"
	restarts >"$WORK/restarts.after"
	[ -z "$(unsettled)" ] && cmp -s "$WORK/restarts.before" "$WORK/restarts.after"
}

# Copies Caddy's internal root certificate, which a DOMAIN=localhost instance serves, to $CURL_CA.
fetch_ca() {
	deadline=$(($(date +%s) + 120))
	until compose exec -T frontend cat /data/caddy/pki/authorities/local/root.crt >"$CURL_CA" 2>/dev/null && [ -s "$CURL_CA" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 2
	done
}

# Runs one SQL statement on database $1 as postgres, printing bare rows.
sql() {
	# shellcheck disable=SC2016 # expanded in the db container
	compose exec -T db sh -c 'if [ -f /run/codeclarity/env ]; then . /run/codeclarity/env; fi
		PGPASSWORD="$POSTGRES_PASSWORD" psql -XqtA -U postgres -d "$1" -c "$2"' sql "$1" "$2"
}

api_curl() {
	if [ -n "${CURL_CA:-}" ]; then
		curl --cacert "$CURL_CA" "$@"
	else
		curl "$@"
	fi
}

# Prints a token for the login account, or nothing if login fails.
login() {
	api_curl -fsS -X POST "$API_BASE/auth/authenticate" -H 'Content-Type: application/json' \
		-d "{\"email\":\"$LOGIN_EMAIL\",\"password\":\"$LOGIN_PASSWORD\"}" 2>/dev/null | jq -er '.data.token' 2>/dev/null || true
}

# Waits for the API to accept the login account, then sets token.
wait_for_login() {
	deadline=$(($(date +%s) + LOGIN_WAIT_SECONDS))
	token=$(login)
	while [ -z "$token" ] && [ "$(date +%s)" -lt "$deadline" ]; do
		sleep 5
		token=$(login)
	done
}

get() {
	api_curl -fsS "$API_BASE$1" -H "Authorization: Bearer $token"
}

# POSTs the JSON $2 to path $1.
post() {
	api_curl -fsS -X POST "$API_BASE$1" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$2"
}

# Writes a tiny npm project (one dependency, ms@2.1.3) as the tar.gz archive $1.
npm_project_archive() {
	src="$WORK/npm-project"
	mkdir -p "$src"
	cat >"$src/package.json" <<'EOF'
{ "name": "fresh-install-app", "version": "1.0.0", "dependencies": { "ms": "2.1.3" } }
EOF
	cat >"$src/package-lock.json" <<'EOF'
{
  "name": "fresh-install-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "fresh-install-app", "version": "1.0.0", "dependencies": { "ms": "2.1.3" } },
    "node_modules/ms": {
      "version": "2.1.3",
      "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="
    }
  }
}
EOF
	tar -czf "$1" -C "$src" package.json package-lock.json
}

# Uploads the tar.gz archive $3 as the source of project $2 in org $1.
upload_archive() {
	api_curl -fsS -X PATCH "$API_BASE/org/$1/file/$2/upload" -H "Authorization: Bearer $token" \
		--form-string type=source --form-string file_name=app.tar.gz --form-string chunk=true \
		--form-string id=0 --form-string last=true --form-string "hash=$(sha256sum "$3" | cut -d' ' -f1)" \
		-F "file=@$3;filename=app.tar.gz" >/dev/null
}

# Starts the Default Analyzer on the uploaded project $2 in org $1 and prints the analysis id.
start_analysis() {
	analyzer=$(get "/org/$1/analyzers?page=0&entries_per_page=100" |
		jq -er '[.data[] | select(.name == "Default Analyzer")][0].id') || return 1
	# The same config the frontend sends: each SBOM plugin gets the uploaded project's path.
	project_path="$1/projects/$2/main"
	body='{"analyzer_id":"'"$analyzer"'","branch":"main","config":{"js-sbom":{"branch":"main","project":"'"$project_path"'"},"php-sbom":{"branch":"main","project":"'"$project_path"'"},"vuln-finder":{"vulnerabilityPolicy":[]},"license-finder":{"licensePolicy":[]}}}'
	post "/org/$1/projects/$2/analyses" "$body" | jq -er '.id'
}

# Polls analysis $3 of project $2 in org $1 into $WORK/analysis.json until it ends, then sets status.
# Succeeds if it completed with every step succeeded or skipped.
wait_analysis() {
	deadline=$(($(date +%s) + ${ANALYSIS_WAIT_SECONDS:-1200}))
	while :; do
		get "/org/$1/projects/$2/analyses/$3" >"$WORK/analysis.json" 2>/dev/null || :
		status=$(jq -r '.data.status // empty' "$WORK/analysis.json" 2>/dev/null) || status=
		case "$status" in completed | failure | cancelled) break ;; esac
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep "${ANALYSIS_POLL_SECONDS:-10}"
	done
	[ "$status" = completed ] || return 1
	jq -e '[.data.steps[][] | .Status] | length > 0 and all(. == "success" or . == "skipped")' "$WORK/analysis.json" >/dev/null 2>&1
}

# Imports a tiny npm project as an uploaded archive in org $2 (no OAuth integration), runs the
# Default Analyzer on it, and checks it completes with every step succeeded; $1 names the run.
check_analysis() {
	archive="$WORK/app.tar.gz"
	npm_project_archive "$archive"
	result=ok
	project=$(post "/org/$2/projects" '{"name":"fresh-install-app","description":"Fresh install test"}' | jq -er '.id') || result=bad
	if [ "$result" = ok ]; then
		upload_archive "$2" "$project" "$archive" || result=bad
	fi
	check "$1: a project is imported from an uploaded archive" $result
	[ "$result" = ok ] || return 0

	result=ok
	analysis=$(start_analysis "$2" "$project") || result=bad
	check "$1: an analysis with the Default Analyzer starts" $result
	[ "$result" = ok ] || return 0

	result=ok
	wait_analysis "$2" "$project" "$analysis" || result=bad
	check "$1: the analysis completes with every step succeeded (status ${status:-none})" $result
	if [ "$result" = bad ]; then
		jq '.data | {status, stage, steps: [.steps[][] | {name: .Name, status: .Status}]}' "$WORK/analysis.json" 2>/dev/null || true
		# shellcheck disable=SC2086 # a list of service names
		report $ANALYSIS_SERVICES
	fi
}
