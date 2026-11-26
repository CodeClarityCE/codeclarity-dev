#!/usr/bin/env bats
# Tests dismiss-scorecard-alerts.sh against the stand-in gh in stubs/, which keeps the org's open
# code-scanning alerts in one file, serves file contents from a folder, and marks an alert
# dismissed when the script dismisses it.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	ALERTS="$BATS_TEST_TMPDIR/alerts.json"
	CONTENTS="$BATS_TEST_TMPDIR/contents"
	echo '[]' >"$ALERTS"
	mkdir -p "$CONTENTS"
	export ALERTS CONTENTS
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	local path
	if [[ "$1 $2" == "api --paginate" && "$3" == orgs/CodeClarityCE/code-scanning/alerts* ]]; then
		local tool="${3#*tool_name=}"
		tool="${tool%%&*}"
		jq -c --arg t "$tool" '[.[] | select(.state == "open" and .tool.name == $t)]' "$ALERTS"
		return
	fi
	if [[ "$1 $2 $3" == "api -H Accept: application/vnd.github.raw" ]]; then
		# repos/CodeClarityCE/<repo>/contents/<path>?ref=<sha>
		path="${4#repos/CodeClarityCE/}"
		path="${path%%\?ref=*}"
		path="${path/\/contents\///}"
		[[ -f "$CONTENTS/$path" ]] || { echo "HTTP 404: Not Found" >&2; return 1; }
		cat "$CONTENTS/$path"
		return
	fi
	if [[ "$1 $2 $3" == "api -X PATCH" ]]; then
		path="${4#repos/CodeClarityCE/}"
		local repo="${path%%/*}" number="${path##*/}"
		jq --arg r "$repo" --argjson n "$number" \
			'map(if .repository.name == $r and .number == $n then .state = "dismissed" else . end)' \
			"$ALERTS" >"$ALERTS.new" && mv "$ALERTS.new" "$ALERTS"
		echo '{}'
		return
	fi
	echo "unexpected: $*" >&2
	return 1
}
RULES
}

# Adds an open alert: <repo> <number> <tool> <rule> <path> <line> [message].
alert() {
	jq --arg r "$1" --argjson n "$2" --arg t "$3" --arg rule "$4" --arg p "$5" --argjson l "$6" \
		--arg m "${7:-score is 3}" \
		'. + [{number: $n, state: "open", repository: {name: $r}, tool: {name: $t}, rule: {id: $rule},
			most_recent_instance: {commit_sha: "abc123", message: {text: $m},
				location: {path: $p, start_line: $l}}}]' "$ALERTS" >"$ALERTS.new"
	mv "$ALERTS.new" "$ALERTS"
}

# Adds a Scorecard alert with no file, as the repo-level checks have.
repo_alert() {
	alert "$1" "$2" Scorecard "$3" "no file associated with this alert" 1 "${4:-score is 3}"
}

# Writes <content> as file <path> of <repo>, served by the contents API.
content() {
	mkdir -p "$(dirname "$CONTENTS/$1/$2")"
	printf '%s\n' "$3" >"$CONTENTS/$1/$2"
}

# The alert numbers of <repo> that were dismissed, space separated.
dismissed() {
	grep "api -X PATCH repos/CodeClarityCE/$1/code-scanning/alerts/" "$GH_STUB_LOG" |
		sed -E 's#.*/code-scanning/alerts/([0-9]+) .*#\1#' | tr '\n' ' ' | sed 's/ $//'
}

dismiss() {
	bash "$ROOT_DIR/scripts/dismiss-scorecard-alerts.sh" "$@"
}

@test "PinnedDependencies on our own .github workflow at v1 is dismissed, a third-party action is not" {
	content api .github/workflows/ci.yml $'jobs:\n  node:\n    uses: CodeClarityCE/.github/.github/workflows/node-image.yml@v1\n  x:\n    uses: actions/checkout@v7'
	alert api 1 Scorecard PinnedDependenciesID .github/workflows/ci.yml 3
	alert api 2 Scorecard PinnedDependenciesID .github/workflows/ci.yml 5

	run dismiss
	echo "$output"
	[ "$status" -eq 0 ]
	[ "$(dismissed api)" = "1" ]
	grep -qF "api/code-scanning/alerts/1 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=ADR 0009" "$GH_STUB_LOG"
}

@test "PinnedDependencies on an exact corepack install in a Dockerfile is dismissed, dlv@latest is not" {
	content frontend .cloud/docker/Dockerfile $'FROM node@sha256:abc\nRUN npm install -g corepack@0.36.0 --force && corepack enable\nRUN go install github.com/go-delve/delve/cmd/dlv@latest'
	content frontend .cloud/scripts/e2e.sh $'npm install -g corepack@0.36.0'
	alert frontend 5 Scorecard PinnedDependenciesID .cloud/docker/Dockerfile 2
	alert frontend 6 Scorecard PinnedDependenciesID .cloud/docker/Dockerfile 3
	alert frontend 7 Scorecard PinnedDependenciesID .cloud/scripts/e2e.sh 1

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed frontend)" = "5" ]
	grep -qF "frontend/code-scanning/alerts/5 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=corepack" "$GH_STUB_LOG"
}

@test "PinnedDependencies on the broker client's local socket call is dismissed, a real download is not" {
	content codeclarity-dev .devcontainer/broker-client.sh $'curl -sS --no-buffer --unix-socket "$socket" -X POST "$@" "http://broker/$command" | perl -e \'\ncurl -sSL https://example.com/install.sh | sh'
	content api .devcontainer/broker-client.sh $'curl -sS --no-buffer --unix-socket "$socket" -X POST "$@" "http://broker/$command" | perl -e \''
	alert codeclarity-dev 8 Scorecard PinnedDependenciesID .devcontainer/broker-client.sh 1
	alert codeclarity-dev 9 Scorecard PinnedDependenciesID .devcontainer/broker-client.sh 2
	alert api 10 Scorecard PinnedDependenciesID .devcontainer/broker-client.sh 1

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed codeclarity-dev)" = "8" ]
	[ "$(dismissed api)" = "" ]
	grep -qF "codeclarity-dev/code-scanning/alerts/8 -f state=dismissed -f dismissed_reason=false positive -f dismissed_comment=Not a download" "$GH_STUB_LOG"
}

@test "PinnedDependencies in the .github repo's fixtures is dismissed as used in tests, elsewhere it is not" {
	alert .github 2 Scorecard PinnedDependenciesID fixtures/node-image/.cloud/docker/Dockerfile 8
	alert api 3 Scorecard PinnedDependenciesID fixtures/node-image/.cloud/docker/Dockerfile 8
	content api fixtures/node-image/.cloud/docker/Dockerfile 'x'

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed .github)" = "2" ]
	[ "$(dismissed api)" = "" ]
	grep -qF ".github/code-scanning/alerts/2 -f state=dismissed -f dismissed_reason=used in tests" "$GH_STUB_LOG"
}

@test "Vulnerabilities naming only GO-2026-5932 is dismissed, any other advisory is not" {
	repo_alert service-knowledge 8 VulnerabilitiesID $'score is 9: 1 existing vulnerabilities detected:\nWarn: Project is vulnerable to: https://osv.dev/GO-2026-5932\nClick Remediation'
	repo_alert frontend 9 VulnerabilitiesID $'score is 9: 1 existing vulnerabilities detected:\nWarn: Project is vulnerable to: https://osv.dev/GHSA-mrhx-c7xc-m3w5'
	repo_alert codeclarity-dev 3 VulnerabilitiesID $'score is 8: 2 existing vulnerabilities detected:\nWarn: Project is vulnerable to: https://osv.dev/GO-2026-5932\nWarn: Project is vulnerable to: https://osv.dev/GO-2026-1111'

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed service-knowledge)" = "8" ]
	[ "$(dismissed frontend)" = "" ]
	[ "$(dismissed codeclarity-dev)" = "" ]
}

@test "BranchProtection is dismissed in every repo except .github" {
	repo_alert api 12 BranchProtectionID
	repo_alert .github 1 BranchProtectionID

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed api)" = "12" ]
	[ "$(dismissed .github)" = "" ]
	grep -qF "api/code-scanning/alerts/12 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=Single active maintainer" "$GH_STUB_LOG"
}

@test "CodeReview, Fuzzing, CIIBestPractices and CITests are dismissed in every repo" {
	repo_alert .github 3 CodeReviewID
	repo_alert api 4 FuzzingID
	repo_alert api 5 CIIBestPracticesID
	repo_alert backend 6 CITestsID

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed .github)" = "3" ]
	[ "$(dismissed api)" = "4 5" ]
	[ "$(dismissed backend)" = "6" ]
	grep -qF "/alerts/4 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=No fuzz targets" "$GH_STUB_LOG"
	grep -qF "/alerts/5 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=Not pursuing the OpenSSF" "$GH_STUB_LOG"
}

@test "the CodeQL TLS alert is dismissed only in its three repos and files" {
	alert utility-dbhelper 12 CodeQL go/disabled-certificate-check helper/Postgres.go 40
	alert utility-boilerplates 13 CodeQL go/disabled-certificate-check plugin_base.go 10
	alert utility-amqp-helper 11 CodeQL go/disabled-certificate-check main.go 20
	alert utility-amqp-helper 14 CodeQL go/disabled-certificate-check other.go 5
	alert service-knowledge 15 CodeQL go/disabled-certificate-check main.go 5
	alert utility-dbhelper 16 CodeQL go/sql-injection helper/Postgres.go 50

	run dismiss
	echo "$output"
	[ "$status" -eq 0 ]
	[ "$(dismissed utility-dbhelper)" = "12" ]
	[ "$(dismissed utility-boilerplates)" = "13" ]
	[ "$(dismissed utility-amqp-helper)" = "11" ]
	[ "$(dismissed service-knowledge)" = "" ]
	grep -qF "utility-dbhelper/code-scanning/alerts/12 -f state=dismissed -f dismissed_reason=won't fix -f dismissed_comment=require means encrypt without verifying, by libpq definition; production uses verify-ca; a startup warning now flags require mode" "$GH_STUB_LOG"
	# Other CodeQL rules are out of scope: not dismissed, not listed.
	[[ "$output" != *"go/sql-injection"* ]]
}

@test "checks we fix are never dismissed" {
	repo_alert api 20 SecurityPolicyID
	repo_alert api 21 LicenseID
	repo_alert api 22 BinaryArtifactsID
	repo_alert api 23 SASTID

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed api)" = "" ]
	grep -qx "api: 0 dismissed, 4 left open" <<<"$output"
}

@test "--dry-run lists what it would dismiss and what it leaves open per repo, and changes nothing" {
	repo_alert api 4 FuzzingID
	repo_alert api 23 SASTID
	content api .github/workflows/ci.yml '    uses: actions/checkout@v7'
	alert api 2 Scorecard PinnedDependenciesID .github/workflows/ci.yml 1

	run dismiss --dry-run
	echo "$output"
	[ "$status" -eq 0 ]
	grep -qx "  would dismiss api#4 FuzzingID (won't fix)" <<<"$output"
	grep -qx "  left open api#23 SASTID" <<<"$output"
	grep -qx "  left open api#2 PinnedDependenciesID .github/workflows/ci.yml:1" <<<"$output"
	grep -qx "api: 1 would be dismissed, 2 left open" <<<"$output"
	[ "$(grep -c PATCH "$GH_STUB_LOG")" -eq 0 ]
}

@test "a re-run right after dismisses nothing" {
	repo_alert api 4 FuzzingID
	repo_alert backend 5 CodeReviewID

	run dismiss
	[ "$status" -eq 0 ]
	grep -qx "api: 1 dismissed, 0 left open" <<<"$output"

	: >"$GH_STUB_LOG"
	run dismiss
	[ "$status" -eq 0 ]
	[ "$(grep -c PATCH "$GH_STUB_LOG")" -eq 0 ]
}

@test "an alert whose file cannot be read is left open" {
	alert api 2 Scorecard PinnedDependenciesID .github/workflows/gone.yml 3

	run dismiss
	[ "$status" -eq 0 ]
	[ "$(dismissed api)" = "" ]
	grep -qx "api: 0 dismissed, 1 left open" <<<"$output"
}

@test "a failed dismissal is reported, the rest still go through, and the run fails" {
	repo_alert api 4 FuzzingID
	repo_alert api 5 CodeReviewID
	# The stand-in gh drops the connection on alert 4.
	# shellcheck disable=SC2016 # the $ signs belong to the stub code, not this shell
	sed -i 's|if \[\[ "$1 $2 $3" == "api -X PATCH" \]\]; then|if [[ "$1 $2 $3" == "api -X PATCH" \&\& "$4" == */alerts/4 ]]; then echo "unexpected EOF" >\&2; return 1; fi\n\tif [[ "$1 $2 $3" == "api -X PATCH" ]]; then|' "$GH_STUB_RULES"

	run dismiss
	[ "$status" -ne 0 ]
	[[ "$output" == *"api#4: dismissal failed"* ]]
	[[ "$output" == *"api: 1 dismissed, 0 left open, 1 failed"* ]]
	[ "$(dismissed api)" = "4 5" ]
}

@test "alerts that cannot be listed stop the run before any dismissal" {
	repo_alert api 4 FuzzingID
	# The stand-in gh refuses the CodeQL listing.
	# shellcheck disable=SC2016 # the $ signs belong to the stub code, not this shell
	sed -i 's|^gh_stub() {|gh_stub() {\n\t[[ "$3" == *tool_name=CodeQL* ]] \&\& { echo "HTTP 403" >\&2; return 1; }|' "$GH_STUB_RULES"

	run dismiss
	[ "$status" -ne 0 ]
	[[ "$output" == *"could not list CodeQL alerts"* ]]
	[ "$(grep -c PATCH "$GH_STUB_LOG")" -eq 0 ]
}

@test "an unknown argument is refused before any gh call" {
	run dismiss --yes
	[ "$status" -ne 0 ]
	[ ! -s "$GH_STUB_LOG" ]
}

@test "--help prints usage and makes no gh call" {
	run dismiss --help
	[ "$status" -eq 0 ]
	grep -q -- "--dry-run" <<<"$output"
	grep -q "SCORECARD_ALERTS_ORG" <<<"$output"
	[ ! -s "$GH_STUB_LOG" ]
}
