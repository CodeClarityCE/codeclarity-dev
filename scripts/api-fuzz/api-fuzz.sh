#!/usr/bin/env bash
# API fuzzing: runs the pinned Schemathesis image against a running instance's OpenAPI description,
# failing on a 5xx or a response that breaks the schema, and keeps the ci-failure issue of the
# nightly run up to date. See README.md.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
API_URL=${API_URL:-https://localhost/api}
MAX_TIME=${MAX_TIME:-1200}
SCHEMATHESIS_IMAGE=${SCHEMATHESIS_IMAGE:-$(cat "$here/schemathesis-image.txt")}
CHECKS=not_a_server_error,response_schema_conformance

usage() {
	cat >&2 <<'EOF'
usage: api-fuzz.sh run --auth PROVIDER --out DIR [--seed N] [-- SCHEMATHESIS_ARGS...]
       api-fuzz.sh issue-token
       api-fuzz.sh issue-body DIR
       api-fuzz.sh report DIR
run fuzzes the API at API_URL as PROVIDER (dev-account, token) and records the run in DIR;
issue-token prints the secret of a new Organization token for the token provider's API_TOKEN;
issue-body prints the ci-failure issue text for a recorded run; report opens, comments on or
closes that issue with gh. Env: API_URL, CURL_CA, MAX_TIME, SCHEMATHESIS_IMAGE, API_TOKEN, RUN_URL.
EOF
	exit "${1:-2}"
}

die() {
	echo "api fuzz: $*" >&2
	exit 1
}

api_curl() {
	if [[ -n "${CURL_CA:-}" ]]; then
		curl --cacert "$CURL_CA" "$@"
	else
		curl "$@"
	fi
}

# Auth providers: auth_<name> prints the header Schemathesis sends on every request.
auth_providers() {
	declare -F | awk '$3 ~ /^auth_/ && $3 != "auth_providers" { sub("^auth_", "", $3); gsub("_", "-", $3); print $3 }'
}

# Prints a JWT of the dev account, logged in through the API.
dev_login() {
	local email=${LOGIN_EMAIL:-john.doe@codeclarity.io} password=${LOGIN_PASSWORD:-'ThisIs4Str0ngP4ssW0rd?'}
	api_curl -fsS -X POST "$API_URL/auth/authenticate" -H 'Content-Type: application/json' \
		-d "$(jq -cn --arg e "$email" --arg p "$password" '{email: $e, password: $p}')" 2>/dev/null |
		jq -er '.data.token' 2>/dev/null || die "$email could not log in through $API_URL"
}

# The dev account, logged in through the API.
auth_dev_account() {
	local token
	token=$(dev_login) || exit 1
	echo "Authorization: Bearer $token"
}

# A bearer token given in API_TOKEN, such as an Organization token.
auth_token() {
	[[ -n "${API_TOKEN:-}" ]] || die "the token provider needs API_TOKEN"
	echo "Authorization: Bearer $API_TOKEN"
}

# Issues an analyze Organization token, valid for a day, in the dev account's personal
# organization and prints its secret, for the token provider's API_TOKEN.
cmd_issue_token() {
	local jwt org secret
	jwt=$(dev_login) || exit 1
	org=$(api_curl -fsS "$API_URL/org?page=0&entries_per_page=50" -H "Authorization: Bearer $jwt" 2>/dev/null |
		jq -er '[.data[].organization | select(.personal)][0].id' 2>/dev/null) ||
		die "found no personal organization of the dev account"
	secret=$(api_curl -fsS -X POST "$API_URL/org/$org/tokens" -H "Authorization: Bearer $jwt" \
		-H 'Content-Type: application/json' \
		-d "$(jq -cn '{name: "api-fuzz", scope: "analyze", expires_on: (now + 86400 | todate)}')" 2>/dev/null |
		jq -er '.data.secret | select(. != "")' 2>/dev/null) ||
		die "could not issue an Organization token in organization $org"
	echo "$secret"
}

cmd_run() {
	local auth='' out='' seed='' extra=() header excluded=() op status
	while (($#)); do
		case "$1" in
		--auth)
			auth=$2
			shift
			;;
		--out)
			out=$2
			shift
			;;
		--seed)
			seed=$2
			shift
			;;
		--)
			shift
			extra=("$@")
			break
			;;
		*) usage ;;
		esac
		shift
	done
	[[ -n "$auth" && -n "$out" ]] || usage
	# grep reads the whole list: -q would stop early and fail the pipeline under pipefail.
	if ! auth_providers | grep -xF "$auth" >/dev/null; then
		echo "api fuzz: unknown auth provider '$auth'; known: $(auth_providers | paste -sd' ')" >&2
		exit 2
	fi
	header=$("auth_${auth//-/_}") || exit 1

	mkdir -p "$out"
	out=$(cd "$out" && pwd)
	echo "$auth" >"$out/auth"
	while read -r op; do
		excluded+=(--exclude-operation-id "$op")
	done < <(grep -v -e '^#' -e '^$' "$here/excluded-operations.txt")

	# Paths are mounted at the same place, so the reports and CA keep their names.
	local docker=(docker run --rm --network host --user "$(id -u):$(id -g)" -v "$out:$out" -w "$out")
	local tls=()
	if [[ -n "${CURL_CA:-}" ]]; then
		docker+=(-v "$CURL_CA:$CURL_CA:ro")
		tls=(--tls-verify "$CURL_CA")
	fi
	[[ -z "$seed" ]] || extra=(--seed "$seed" "${extra[@]}")

	echo "api fuzz: $SCHEMATHESIS_IMAGE against $API_URL as $auth for up to ${MAX_TIME}s"
	set +e
	"${docker[@]}" "$SCHEMATHESIS_IMAGE" run "$API_URL/api_doc-json" \
		--url "$API_URL" \
		--header "$header" \
		--checks "$CHECKS" \
		"${excluded[@]}" \
		"${tls[@]}" \
		--max-time "$MAX_TIME" \
		--request-timeout 60 \
		--wait-for-schema 60 \
		--report junit --report-junit-path "$out/junit.xml" \
		--no-color \
		"${extra[@]}" 2>&1 | tee "$out/schemathesis.log"
	status=${PIPESTATUS[0]}
	set -e
	echo "$status" >"$out/exit-code"
	return "$status"
}

# Prints the lines of section $2 (ERRORS, FAILURES) of Schemathesis log $1, without its banner.
log_section() {
	awk -v name="$2" '
		/^=+ [A-Z]+ =+$/ { on = ($2 == name); next }
		/^=+ .* in [0-9.]+s =+$/ { on = 0 }
		on && !/^Need more help\?$/ && !/Join our Discord server/ && !/^ +st replay / { print }
	' "$1"
}

cmd_issue_body() {
	local dir=${1:-} auth seed log limit=50000 details
	[[ -n "$dir" ]] || usage
	auth=$(cat "$dir/auth" 2>/dev/null || echo unknown)
	log="$dir/schemathesis.log"
	echo "<!-- api-fuzz: $auth -->"
	echo
	if [[ ! -f "$dir/exit-code" || ! -f "$log" ]]; then
		echo "The nightly API fuzz run as \`$auth\` failed: Schemathesis did not run, so the stack or the login failed. See ${RUN_URL:-the run logs}."
		return
	fi
	seed=$(sed -n 's/^Seed: \([0-9]*\)$/\1/p' "$log" | tail -n1)
	echo "The nightly API fuzz run as \`$auth\` found a 5xx, a response that breaks the OpenAPI schema, or a request error (${RUN_URL:-run link not set})."
	echo
	echo "Each case below ends with the request to replay; Schemathesis hides the token and values that look secret as \`[Filtered]\`. To rerun the same cases (see scripts/api-fuzz/README.md):"
	echo
	echo '```sh'
	echo "API_URL=https://localhost/api bash scripts/api-fuzz/api-fuzz.sh run --auth $auth --out DIR --seed ${seed:-SEED}"
	echo '```'
	echo
	echo "Once fixed, commit each case as a test in \`api/test/integration/api-fuzz-regressions.integration.e2e-spec.ts\`."
	echo
	details=$({
		if [[ -n "$(log_section "$log" FAILURES)" ]]; then
			echo "### Failures"
			echo
			echo '```'
			log_section "$log" FAILURES
			echo '```'
		fi
		if [[ -n "$(log_section "$log" ERRORS)" ]]; then
			echo
			echo "### Errors"
			echo
			echo '```'
			log_section "$log" ERRORS
			echo '```'
		fi
	})
	if ((${#details} > limit)); then
		printf '%s\n```\n\nOutput truncated; the whole log is in the run'"'"'s artifact.\n' "${details:0:limit}"
	else
		printf '%s\n' "$details"
	fi
}

# Opens or comments on the provider's ci-failure issue after a failed run; closes it after a green one.
cmd_report() {
	local dir=${1:-} auth title marker issue labels body
	[[ -n "$dir" ]] || usage
	auth=$(cat "$dir/auth" 2>/dev/null || echo unknown)
	title="API fuzz failing as $auth"
	marker="<!-- api-fuzz: $auth -->"
	issue=$(gh issue list --label ci-failure --state open --limit 100 --json number,title,body |
		jq -r --arg t "$title" --arg m "$marker" \
			'[.[] | select(.title == $t or (.body | contains($m)))] | sort_by(.number) | first | .number // empty')

	if [[ "$(cat "$dir/exit-code" 2>/dev/null)" == 0 ]]; then
		if [[ -z "$issue" ]]; then
			echo "api fuzz: green as $auth; no open issue."
			return
		fi
		gh issue comment "$issue" --body "The nightly API fuzz run as \`$auth\` is green again (${RUN_URL:-no run link}). Closing."
		gh issue close "$issue"
		return
	fi

	labels=$(gh label list --limit 500 --json name --jq '.[].name')
	grep -qxF ci-failure <<<"$labels" ||
		gh label create ci-failure --color B60205 --description "The CI required check failed on main or develop"
	grep -qxF needs-triage <<<"$labels" ||
		gh label create needs-triage --color FBCA04 --description "Needs triage"
	body=$(cmd_issue_body "$dir")
	if [[ -n "$issue" ]]; then
		gh issue comment "$issue" --body "$body"
		echo "api fuzz: commented on #$issue."
	else
		gh issue create --title "$title" --label ci-failure --label needs-triage --body "$body"
	fi
}

case ${1:-} in
run)
	shift
	cmd_run "$@"
	;;
issue-token) cmd_issue_token ;;
issue-body) cmd_issue_body "${2:-}" ;;
report) cmd_report "${2:-}" ;;
*) usage ;;
esac
