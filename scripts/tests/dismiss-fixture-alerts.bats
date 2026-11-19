#!/usr/bin/env bats
# Tests dismiss-fixture-alerts.sh against the stand-in gh in stubs/, which keeps each repo's
# open Dependabot alerts in a file and drops an alert from it when it is dismissed.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	ALERTS="$BATS_TEST_TMPDIR/alerts"
	mkdir -p "$ALERTS"
	export ALERTS
	# Every repo the script reads starts with no open alerts.
	for repo in plugin-sbom-javascript plugin-sca-patching plugin-sbom-php codeclarity-dev .github; do
		echo '[]' >"$ALERTS/$repo"
	done
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	local repo
	if [[ "$1 $2" == "api --paginate" ]]; then
		repo="${3#repos/CodeClarityCE/}"
		repo="${repo%%/*}"
		[[ -f "$ALERTS/$repo" ]] || { echo "HTTP 403: Dependabot alerts are disabled" >&2; return 1; }
		jq -c '[.[] | select(.state == "open")]' "$ALERTS/$repo"
		return
	fi
	if [[ "$1 $2 $3" == "api -X PATCH" ]]; then
		repo="${4#repos/CodeClarityCE/}"
		local number="${repo##*/}"
		repo="${repo%%/*}"
		jq --argjson n "$number" 'map(if .number == $n then .state = "dismissed" else . end)' \
			"$ALERTS/$repo" >"$ALERTS/$repo.new" && mv "$ALERTS/$repo.new" "$ALERTS/$repo"
		echo '{}'
		return
	fi
	echo "unexpected: $*" >&2
	return 1
}
RULES
}

# Gives <repo> open alerts, each "<number>:<manifest path>".
alerts() {
	local repo="$1" spec
	shift
	for spec; do
		jq -n --argjson n "${spec%%:*}" --arg p "${spec#*:}" \
			'{number: $n, state: "open", dependency: {manifest_path: $p}}'
	done | jq -s . >"$ALERTS/$repo"
}

# The alert numbers of <repo> that were dismissed, space separated.
dismissed() {
	grep "api -X PATCH repos/CodeClarityCE/$1/dependabot/alerts/" "$GH_STUB_LOG" |
		sed -E 's#.*/dependabot/alerts/([0-9]+).*#\1#' | tr '\n' ' ' | sed 's/ $//'
}

dismiss() {
	bash "$ROOT_DIR/scripts/dismiss-fixture-alerts.sh" "$@"
}

@test "only alerts whose manifest is inside a known fixture folder are dismissed" {
	alerts plugin-sbom-javascript 1:tests/npmv1/package-lock.json 2:go.mod 3:pnpm-lock.yaml \
		4:tests-old/package.json 5:src/tests/package.json 6:tests/yarn_workspace/packages/a/yarn.lock
	alerts codeclarity-dev 10:pnpm-lock.yaml 11:.cloud/scripts/measure/baseline-project/package-lock.json \
		12:scripts/benchmark/fixtures/npm-x/package-lock.json 13:scripts/benchmark/run.sh 14:tests/package.json
	alerts api 20:tests/package-lock.json

	run dismiss
	echo "$output"
	[ "$status" -eq 0 ]
	[ "$(dismissed plugin-sbom-javascript)" = "1 6" ]
	[ "$(dismissed codeclarity-dev)" = "11 12" ]
	[ "$(dismissed api)" = "" ]
}

@test "each dismissal says tolerable risk with the fixture comment" {
	alerts plugin-sbom-php 7:tests/test-vulnerable/composer.lock

	run dismiss
	[ "$status" -eq 0 ]
	grep -qF "plugin-sbom-php/dependabot/alerts/7 -f state=dismissed -f dismissed_reason=tolerable_risk -f dismissed_comment=test fixture: deliberately vulnerable input" "$GH_STUB_LOG"
}

@test "it prints a count per repo, and a re-run dismisses nothing new" {
	alerts plugin-sca-patching 1:tests/a/package-lock.json 2:tests/b/yarn.lock 3:go.mod
	alerts codeclarity-dev 4:scripts/benchmark/fixtures/x/composer.lock

	run dismiss
	[ "$status" -eq 0 ]
	grep -qx "plugin-sca-patching: 2 dismissed" <<<"$output"
	grep -qx "codeclarity-dev: 1 dismissed" <<<"$output"
	grep -qx "plugin-sbom-php: 0 dismissed" <<<"$output"

	: >"$GH_STUB_LOG"
	run dismiss
	[ "$status" -eq 0 ]
	grep -qx "plugin-sca-patching: 0 dismissed" <<<"$output"
	grep -qx "codeclarity-dev: 0 dismissed" <<<"$output"
	[ "$(grep -c PATCH "$GH_STUB_LOG")" -eq 0 ]
}

@test "--dry-run lists what it would dismiss and dismisses nothing" {
	alerts plugin-sbom-javascript 5:tests/npmv1/package-lock.json 6:go.mod

	run dismiss --dry-run
	[ "$status" -eq 0 ]
	grep -qx "  would dismiss plugin-sbom-javascript#5 tests/npmv1/package-lock.json" <<<"$output"
	grep -qx "plugin-sbom-javascript: 1 would be dismissed" <<<"$output"
	[ "$(grep -c "would dismiss" <<<"$output")" -eq 1 ]
	[ "$(grep -c PATCH "$GH_STUB_LOG")" -eq 0 ]
}

@test "a repo whose alerts cannot be listed is reported, the others still run, and it exits non-zero" {
	rm "$ALERTS/.github"
	alerts plugin-sbom-php 8:tests/test1/composer.lock

	run dismiss
	[ "$status" -ne 0 ]
	grep -qx ".github: could not list Dependabot alerts" <<<"$output"
	[ "$(dismissed plugin-sbom-php)" = "8" ]
}

@test "an unknown argument is refused before any gh call" {
	run dismiss --yes
	[ "$status" -ne 0 ]
	[ ! -s "$GH_STUB_LOG" ]
}
