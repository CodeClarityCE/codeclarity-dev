#!/usr/bin/env bats
# Tests private-reporting.sh against the stand-in gh in stubs/, which keeps each repo's private
# vulnerability reporting state in a file and turns it on when the script PUTs it.
# Run from the repo root: bats scripts/tests

# run -1 (exit exactly 1) needs bats 1.5.
bats_require_minimum_version 1.5.0

setup() {
	load helpers
	setup_fake_root
	REPORTING="$BATS_TEST_TMPDIR/reporting"
	mkdir -p "$REPORTING"
	: >"$BATS_TEST_TMPDIR/repos"
	export REPORTING BATS_TEST_TMPDIR
	cat >"$GH_STUB_RULES" <<'RULES'
gh_stub() {
	local repo
	case "$*" in
	"api --paginate orgs/CodeClarityCE/repos?type=all&per_page=100 --jq "*)
		jq -s . "$BATS_TEST_TMPDIR/repos" | jq -r "$5"
		return
		;;
	"api repos/CodeClarityCE/"*"/private-vulnerability-reporting --jq .enabled")
		repo="${2#repos/CodeClarityCE/}"
		repo="${repo%%/*}"
		[[ -f "$REPORTING/$repo" ]] || { echo "HTTP 403: Must have admin rights" >&2; return 1; }
		cat "$REPORTING/$repo"
		return
		;;
	"api -X PUT repos/CodeClarityCE/"*"/private-vulnerability-reporting")
		repo="${4#repos/CodeClarityCE/}"
		repo="${repo%%/*}"
		[[ -f "$REPORTING/$repo" ]] || { echo "HTTP 403: Must have admin rights" >&2; return 1; }
		echo true >"$REPORTING/$repo"
		return
		;;
	esac
	echo "unexpected: $*" >&2
	return 1
}
RULES
}

# Adds a repo to the org listing, with reporting on (true), off (false) or unreadable (unknown),
# and "archived" or "private" as an optional third argument.
repo() {
	jq -nc --arg name "$1" --argjson archived "$([[ "${3:-}" == archived ]] && echo true || echo false)" \
		--arg visibility "$([[ "${3:-}" == private ]] && echo private || echo public)" \
		'{name: $name, archived: $archived, visibility: $visibility}' >>"$BATS_TEST_TMPDIR/repos"
	[[ "$2" == unknown ]] || echo "$2" >"$REPORTING/$1"
}

@test "--check lists every repo where reporting is off and exits non-zero" {
	repo api true
	repo frontend false
	repo backend false
	run "$ROOT_DIR/scripts/private-reporting.sh" --check
	[ "$status" -eq 1 ]
	echo "$output"
	[ "$output" = "api on
frontend off
backend off
2 of 3 public repos have private vulnerability reporting off or unknown" ]
}

@test "--apply turns reporting on only where it is off, then passes the check" {
	repo api true
	repo frontend false
	run "$ROOT_DIR/scripts/private-reporting.sh" --apply
	[ "$status" -eq 0 ]
	echo "$output"
	[ "$output" = "frontend: turned on
api on
frontend on
all 2 public repos have private vulnerability reporting on" ]
	[ "$(grep -c -- '-X PUT' "$GH_STUB_LOG")" -eq 1 ]
	grep -q -- '-X PUT repos/CodeClarityCE/frontend/private-vulnerability-reporting' "$GH_STUB_LOG"
}

@test "--check counts a repo whose state cannot be read and skips archived repos" {
	repo api true
	repo old-plugin false archived
	repo deployment unknown
	run "$ROOT_DIR/scripts/private-reporting.sh" --check
	[ "$status" -eq 1 ]
	echo "$output"
	[ "$output" = "api on
deployment unknown
1 of 2 public repos have private vulnerability reporting off or unknown" ]
}

@test "--check passes when every repo has reporting on" {
	repo api true
	repo frontend true
	run "$ROOT_DIR/scripts/private-reporting.sh" --check
	[ "$status" -eq 0 ]
	[ "$output" = "api on
frontend on
all 2 public repos have private vulnerability reporting on" ]
	run -1 grep -q -- '-X PUT' "$GH_STUB_LOG"
}

@test "with no mode it changes nothing and asks for one" {
	repo frontend false
	run "$ROOT_DIR/scripts/private-reporting.sh"
	[ "$status" -eq 1 ]
	[[ "$output" == *"expected --check or --apply"* ]]
	run -1 grep -q -- '-X PUT' "$GH_STUB_LOG"
}

@test "private repos, where GitHub offers no private reporting, are listed but neither fail nor change" {
	repo api true
	repo admin-tools unknown private
	run "$ROOT_DIR/scripts/private-reporting.sh" --apply
	[ "$status" -eq 0 ]
	[ "$output" = "api on
admin-tools private
all 1 public repos have private vulnerability reporting on" ]
	run -1 grep -q -- '-X PUT' "$GH_STUB_LOG"
}
