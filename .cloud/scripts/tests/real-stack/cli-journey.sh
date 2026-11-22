#!/bin/sh
# Golden journey 7: a CI pipeline analyses a project with the CLI and an Organization token.
# Runs against the trimmed real stack after `stack.sh up`; never against a stack you use.
#
# Usage: sh .cloud/scripts/tests/real-stack/cli-journey.sh OUTDIR
#   OUTDIR receives the CLI's output (analysis.json, results.json) and the token's Audit log entries.
# Env: DEPLOYMENT_DIR (default: the deployment submodule), CLI (a built codeclarity binary;
#      default: built from backend/ in the pinned Go image), E2E_RUN (names this run's data).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
dir=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
OUT=${1:?usage: cli-journey.sh OUTDIR}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
RUN=${E2E_RUN:-$(date +%s)}
API_BASE=https://localhost/api
LOGIN_EMAIL=john.doe@codeclarity.io
LOGIN_PASSWORD='ThisIs4Str0ngP4ssW0rd?'
LOGIN_WAIT_SECONDS=60
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CURL_CA="$WORK/ca.crt"
# Keep in sync with backend/.github/workflows/ci.yml and CodeClarityCE/.github go-checks.yml.
GO_IMAGE=golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d
# ms@0.7.1 has one advisory in the knowledge dump fixture.
ADVISORY='GHSA-w9mr-4mfr-499f|CVE-2017-20162'

compose() {
	docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" -f "$here/docker-compose.yaml" "$@"
}

# shellcheck source=../fresh-install/lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"

# The CLI as a release builds it, unless CLI names one.
build_cli() {
	if [ -n "${CLI:-}" ]; then
		echo "$CLI"
		return
	fi
	docker run --rm -v "$root/backend:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=local -e CGO_ENABLED=0 \
		-e GOFLAGS=-buildvcs=false "$GO_IMAGE" go build -o /src/bin/codeclarity . >&2
	echo "$root/backend/bin/codeclarity"
}

# Issues an Organization token with scope $2, named $1, in $org, and prints its secret.
issue_token() {
	expires=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
	post "/org/$org/tokens" "{\"name\":\"$1\",\"scope\":\"$2\",\"expires_on\":\"$expires\"}" | jq -er '.data.secret'
}

# A pipeline's checkout: an npm project with ms@0.7.1.
write_project() {
	mkdir -p "$1"
	cat >"$1/package.json" <<'EOF'
{ "name": "journey-cli-app", "version": "1.0.0", "dependencies": { "ms": "0.7.1" } }
EOF
	cat >"$1/package-lock.json" <<'EOF'
{
  "name": "journey-cli-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "journey-cli-app", "version": "1.0.0", "dependencies": { "ms": "0.7.1" } },
    "node_modules/ms": {
      "version": "0.7.1",
      "resolved": "https://registry.npmjs.org/ms/-/ms-0.7.1.tgz",
      "integrity": "sha512-lRLiIR9fSNpnP6TC4v8+4OU7oStC01esuNowdQ34L+Gk8e5Puoc88IqJ+XAY/B3Mn2ZKis8l8HX90oU8ivzUHg=="
    }
  }
}
EOF
}

# Runs the CLI as a pipeline step: its own home, the token only in the environment.
cli() {
	HOME="$WORK/home" SSL_CERT_FILE="$CURL_CA" CODECLARITY_TOKEN="$secret" "$cli_bin" "$@"
}

sh "$here/stack.sh" ca "$CURL_CA"
cli_bin=$(build_cli)
mkdir -p "$WORK/home"
wait_for_login
[ -n "$token" ] || {
	echo "cli-journey: $LOGIN_EMAIL could not log in through $API_BASE" >&2
	exit 1
}
org=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)][0].organization.id')
name="journey-7-$RUN"

# An admin issues the pipeline its token.
result=ok
secret=$(issue_token "$name" analyze) || result=bad
check "an admin issues an analyze Organization token" $result
[ "$result" = ok ] || exit 1

result=ok
cli version >"$OUT/version.txt" && grep -q '^codeclarity ' "$OUT/version.txt" || result=bad
check "the CLI prints its version" $result

result=ok
cli login --url "$API_BASE" --org "$org" >"$OUT/login.txt" 2>&1 || result=bad
check "the pipeline logs in with the token from CODECLARITY_TOKEN" $result

write_project "$WORK/checkout"
result=ok
cli analyze "$WORK/checkout" --name "$name" --analyzer "Default Analyzer" --wait --timeout 15m \
	>"$OUT/analysis.json" 2>"$OUT/analyze.log" || result=bad
check "analyze uploads the checkout and waits for the analysis to complete" $result
[ "$result" = ok ] || {
	cat "$OUT/analyze.log" "$OUT/analysis.json" >&2
	report api service-dispatcher service-downloader plugin-js-sbom plugin-vuln-finder plugin-license-finder
	exit 1
}

result=ok
cli results --format json >"$OUT/results.json" 2>"$OUT/results.log" || result=bad
jq -e --arg re "$ADVISORY" '[.findings[] | select((.id | test($re)) and any(.affected[]; .package == "ms" and .version == "0.7.1"))] | length == 1' \
	"$OUT/results.json" >/dev/null || result=bad
check "results --format json lists the ms@0.7.1 advisory" $result

# A read token may read results but not start an analysis.
result=ok
secret=$(issue_token "$name-read" read) || result=bad
if [ "$result" = ok ] && cli analyze "$WORK/checkout" --name "$name-read" >"$OUT/read-analyze.json" 2>"$OUT/read-analyze.log"; then
	result=bad
fi
grep -q "analyze scope" "$OUT/read-analyze.log" || result=bad
check "a read token is refused an analysis" $result

result=ok
get "/org/$org/audit_logs?page=0&entries_per_page=100&search_key=$name" >"$OUT/audit-log.json" || result=bad
used=$(jq --arg name "$name" '[.data[] | select(.blame_on_token_name == $name)] | length' "$OUT/audit-log.json") || result=bad
[ "${used:-0}" -gt 0 ] || result=bad
check "the Audit log names the token as the actor (${used:-0} entries for this run)" $result

echo "cli-journey: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
