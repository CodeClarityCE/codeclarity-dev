#!/usr/bin/env bats
# Tests ci-status.sh: the submodule path map, the status table built from one GraphQL
# query, and waiting on PRs' ci checks. gh is the stand-in in stubs/.
# Run from the repo root: bats scripts/tests

setup() {
	load helpers
	setup_fake_root
	write_file . .gitmodules '[submodule "backend"]
	path = backend
	url = https://github.com/CodeClarityCE/backend.git
[submodule "api"]
	path = api
	url = https://github.com/CodeClarityCE/api.git'
	write_file backend .gitmodules '[submodule "utility-types"]
	path = utilities/types
	url = https://github.com/CodeClarityCE/utility-types.git
[submodule "pluginsbom-javascript"]
	path = plugins/js-sbom
	url = https://github.com/CodeClarityCE/plugin-sbom-javascript.git'
	export POLL_SECONDS=0 WAIT_TIMEOUT_SECONDS=5
}

# A ci check run as the GraphQL query returns it.
check_run() {
	printf '{"name": "ci", "status": "%s", "conclusion": %s, "checkSuite": {"workflowRun": {"event": "%s"}}}' "$@"
}

# A branch whose head commit carries the given contexts.
branch() {
	printf '{"target": {"statusCheckRollup": {"contexts": {"nodes": [%s]}}}}' "$1"
}

# One repository node: name, main, develop, PR numbers (JSON array), branch names (JSON array).
repo_node() {
	printf '{"name": "%s", "main": %s, "develop": %s, "pullRequests": {"nodes": %s}, "refs": {"nodes": %s}}' \
		"$1" "$2" "$3" "$(jq -c 'map({number: .})' <<<"$4")" "$(jq -c 'map({name: .})' <<<"$5")"
}

# Makes gh answer the GraphQL query with these repo nodes, and CI_RELEASE with $CI_RELEASE_<repo>.
answer_status() {
	printf '{"data": {"organization": {"repositories": {"pageInfo": {"hasNextPage": false}, "nodes": [%s]}}}}\n' \
		"$(IFS=,; echo "$*")" >"$BATS_TEST_TMPDIR/graphql.json"
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	case "$1 $2" in
	"api graphql") cat "$BATS_TEST_TMPDIR/graphql.json" ;;
	"api repos/CodeClarityCE/"*/actions/variables/CI_RELEASE)
		local repo="${2#repos/CodeClarityCE/}" file
		file="$BATS_TEST_TMPDIR/vars/${repo%%/*}"
		[[ -f "$file" ]] || { echo "HTTP 404: Not Found" >&2; return 1; }
		cat "$file"
		;;
	*) echo "unexpected: $*" >&2; return 1 ;;
	esac
}
RULES
	export BATS_TEST_TMPDIR
}

# Sets CI_RELEASE for a repo as the REST API would return it.
ci_release() {
	mkdir -p "$BATS_TEST_TMPDIR/vars"
	echo "$2" >"$BATS_TEST_TMPDIR/vars/$1"
}

# --- submodule paths ----------------------------------------------------------------------

@test "submodule_map names repos by the release script's paths, nested ones included" {
	run sourced ci-status.sh submodule_map
	[ "$status" -eq 0 ]
	[ "$output" = "codeclarity-dev .
backend backend
utility-types backend/utilities/types
plugin-sbom-javascript backend/plugins/js-sbom
api api" ]
}

@test "submodule_map skips a submodule that is not checked out" {
	rm "$ROOT_DIR/backend/.gitmodules"
	run sourced ci-status.sh submodule_map
	[ "$output" = "codeclarity-dev .
backend backend
api api" ]
}

# --- status table -------------------------------------------------------------------------

@test "the table shows path, ci per branch, CI_RELEASE, PRs and other branches per repo" {
	answer_status \
		"$(repo_node api "$(branch "$(check_run COMPLETED '"SUCCESS"' push)")" \
			"$(branch "$(check_run IN_PROGRESS null push)")" '[12, 15]' '["main", "develop", "fix/x"]')" \
		"$(repo_node utility-types "$(branch "$(check_run COMPLETED '"FAILURE"' push)")" null '[]' '["main"]')" \
		"$(repo_node sandbox "$(branch '{}')" "$(branch '')" '[]' '["main", "develop", "a", "b"]')"
	ci_release api true
	ci_release utility-types false

	run sourced ci-status.sh status_table
	[ "$status" -eq 0 ]
	echo "$output"
	[ "$(sed -n 1p <<<"$output" | tr -s ' ')" = "PATH REPO MAIN DEVELOP CI_RELEASE PRS BRANCHES" ]
	[ "$(sed -n 2p <<<"$output" | tr -s ' ')" = "- sandbox - - unset - a,b" ]
	[ "$(sed -n 3p <<<"$output" | tr -s ' ')" = "api api success pending true #12 #15 fix/x" ]
	[ "$(sed -n 4p <<<"$output" | tr -s ' ')" = "backend/utilities/types utility-types failure no-branch false - -" ]
}

@test "the table prefers a branch's push run of ci over a pull_request run" {
	answer_status "$(repo_node api \
		"$(branch "$(check_run COMPLETED '"FAILURE"' pull_request),$(check_run COMPLETED '"SUCCESS"' push)")" \
		"$(branch '')" '[]' '[]')"
	run sourced ci-status.sh status_table
	[ "$(sed -n 2p <<<"$output" | tr -s ' ')" = "api api success - unset - -" ]
}

@test "the table comes from one GraphQL query over non-archived repos" {
	answer_status "$(repo_node api null null '[]' '[]')"
	run sourced ci-status.sh status_table
	[ "$status" -eq 0 ]
	[ "$(grep -c 'api graphql' "$GH_STUB_LOG")" -eq 1 ]
	grep -q 'isArchived: false' "$GH_STUB_LOG"
}

# --- waiting on PRs -----------------------------------------------------------------------

# Answers "pr checks <n> -R CodeClarityCE/<repo>" with the next line of $BATS_TEST_TMPDIR/checks/<repo>#<n>,
# then keeps repeating the last line.
answer_checks() {
	mkdir -p "$BATS_TEST_TMPDIR/checks"
	printf '%s\n' "${@:2}" >"$BATS_TEST_TMPDIR/checks/$1"
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	[[ "$1 $2" == "pr checks" ]] || { echo "unexpected: $*" >&2; return 1; }
	local file="$BATS_TEST_TMPDIR/checks/${5#CodeClarityCE/}#$3" n
	n=$(($(cat "$file.calls" 2>/dev/null || echo 0) + 1))
	echo "$n" >"$file.calls"
	sed -n "${n}p" "$file" | grep . || tail -n 1 "$file"
}
RULES
	export BATS_TEST_TMPDIR
}

@test "--wait reports each PR once its pull_request ci finishes" {
	answer_checks 'api#12' \
		'[{"name": "ci", "bucket": "pending", "event": "pull_request"}]' \
		'[{"name": "ci", "bucket": "pass", "event": "pull_request"}]'
	answer_checks 'codeclarity-dev#200' '[{"name": "ci", "bucket": "pass", "event": "pull_request"}]'
	run sourced ci-status.sh main --wait 'api#12' 'codeclarity-dev#200'
	[ "$status" -eq 0 ]
	[ "$output" = "codeclarity-dev#200 pass
api#12 pass" ]
}

@test "--wait exits non-zero when a PR's ci failed" {
	answer_checks 'api#12' '[{"name": "ci", "bucket": "fail", "event": "pull_request"}]'
	answer_checks 'frontend#3' '[{"name": "ci", "bucket": "pass", "event": "pull_request"}]'
	run sourced ci-status.sh main --wait 'api#12' 'frontend#3'
	[ "$status" -eq 1 ]
	[ "$output" = "api#12 fail
frontend#3 pass" ]
}

@test "--wait ignores the push run and other checks" {
	answer_checks 'api#12' \
		'[{"name": "ci", "bucket": "fail", "event": "push"}, {"name": "lint", "bucket": "fail", "event": "pull_request"}]' \
		'[{"name": "ci", "bucket": "fail", "event": "push"}, {"name": "ci", "bucket": "pass", "event": "pull_request"}]'
	run sourced ci-status.sh main --wait 'api#12'
	[ "$status" -eq 0 ]
	[ "$output" = "api#12 pass" ]
}

@test "--wait keeps waiting while no ci is reported, then times out" {
	answer_checks 'api#12' ''
	WAIT_TIMEOUT_SECONDS=0 run sourced ci-status.sh main --wait 'api#12'
	[ "$status" -eq 1 ]
	[ "$output" = "api#12 timeout" ]
}

@test "--wait rejects an argument that is not repo#number" {
	run sourced ci-status.sh main --wait api
	[ "$status" -eq 1 ]
	[[ "$output" == *"expected repo#number, got 'api'"* ]]
}
