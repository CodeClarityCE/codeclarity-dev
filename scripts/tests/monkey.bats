#!/usr/bin/env bats
# Tests scripts/monkey/monkey.sh: the monkey run through the real-stack runner (a stub here),
# the issue body built from its output, and the ci-failure issue (gh is the stub in stubs/).
# Run from the repo root: bats scripts/tests

MONKEY="$BATS_TEST_DIRNAME/../monkey/monkey.sh"
FIXTURE="$BATS_TEST_DIRNAME/fixtures/monkey"

bats_require_minimum_version 1.5.0

setup() {
	PATH="$BATS_TEST_DIRNAME/stubs:$PATH"
	export GH_STUB_LOG="$BATS_TEST_TMPDIR/gh.log"
	export GH_STUB_RULES="$BATS_TEST_TMPDIR/gh-rules.bash"
	export RUNNER_LOG="$BATS_TEST_TMPDIR/runner.log"
	OUT="$BATS_TEST_TMPDIR/out"
	: >"$GH_STUB_LOG"
	stub_runner 0
}

# A stand-in for frontend/.cloud/scripts/e2e-real-stack.sh: logs its arguments and seed, exits with $1.
stub_runner() {
	cat >"$BATS_TEST_TMPDIR/runner.sh" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >"\$RUNNER_LOG"
echo "MONKEY_SEED=\$MONKEY_SEED MONKEY_STEPS=\${MONKEY_STEPS:-}" >>"\$RUNNER_LOG"
exit $1
EOF
	export E2E_REAL_STACK="$BATS_TEST_TMPDIR/runner.sh"
}

@test "run picks a seed, records it and runs the @monkey journeys with it" {
	run bash "$MONKEY" run https://localhost "$OUT"
	[ "$status" -eq 0 ]
	seed=$(cat "$OUT/seed")
	[[ "$seed" =~ ^[0-9]+$ ]]
	[[ "$output" == *"seed $seed"* ]]
	[ "$(sed -n 1p "$RUNNER_LOG")" = https://localhost ]
	[ "$(sed -n 2p "$RUNNER_LOG")" = "$OUT" ]
	[ "$(sed -n 3p "$RUNNER_LOG")" = --grep ]
	[ "$(sed -n 4p "$RUNNER_LOG")" = @monkey ]
	grep -qxF "MONKEY_SEED=$seed MONKEY_STEPS=" "$RUNNER_LOG"
	[ "$(cat "$OUT/exit-code")" = 0 ]
}

@test "run replays the seed given in MONKEY_SEED and passes extra options on" {
	MONKEY_SEED=77 MONKEY_STEPS=10 run bash "$MONKEY" run https://localhost "$OUT" --grep "monkey results seed"
	[ "$status" -eq 0 ]
	[ "$(cat "$OUT/seed")" = 77 ]
	grep -qxF "MONKEY_SEED=77 MONKEY_STEPS=10" "$RUNNER_LOG"
	grep -qxF "monkey results seed" "$RUNNER_LOG"
}

@test "run refuses a seed that is not a number, without evaluating it" {
	MONKEY_SEED='x[$(touch '"$BATS_TEST_TMPDIR"'/ran)]' run bash "$MONKEY" run https://localhost "$OUT"
	[ "$status" -ne 0 ]
	[[ "$output" == *"MONKEY_SEED must be a number"* ]]
	[ ! -e "$BATS_TEST_TMPDIR/ran" ]
	[ ! -e "$RUNNER_LOG" ]
}

@test "run fails with the runner's exit code and records it" {
	stub_runner 1
	run bash "$MONKEY" run https://localhost "$OUT"
	[ "$status" -eq 1 ]
	[ "$(cat "$OUT/exit-code")" = 1 ]
}

# A recorded failed run in $OUT, with the fixture's failing page.
recorded() {
	mkdir -p "$OUT"
	cp -r "$FIXTURE/." "$OUT/"
	echo 1234 >"$OUT/seed"
	echo "$1" >"$OUT/exit-code"
}

@test "issue-body gives the seed, each failing page's problems and actions, the replay and the trace" {
	recorded 1
	RUN_URL=https://github.com/o/r/actions/runs/7 run bash "$MONKEY" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"<!-- monkey -->"* ]]
	[[ "$output" == *"seed 1234"* ]]
	[[ "$output" == *"### monkey results, seed 1234"* ]]
	[[ "$output" == *"step 7: uncaught error: Cannot read properties of undefined"* ]]
	[[ "$output" == *'1. click tab "SBOM"'* ]]
	[[ "$output" == *'MONKEY_SEED=1234 MONKEY_STEPS=60 bash scripts/monkey/monkey.sh run https://localhost DIR'* ]]
	[[ "$output" == *"test-results/monkey-journey-monkey-results-seed-real-stack/trace.zip"* ]]
	[[ "$output" == *"https://github.com/o/r/actions/runs/7"* ]]
	[[ "$output" == *"MONKEY_REGRESSIONS"* ]]
}

@test "issue-body says when the monkey never ran" {
	mkdir -p "$OUT"
	run bash "$MONKEY" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"did not run"* ]]
}

@test "issue-body names a failure without a monkey report, such as a page that would not open" {
	mkdir -p "$OUT/test-results/monkey-journey-monkey-ticket-seed-real-stack"
	echo 99 >"$OUT/seed"
	echo 1 >"$OUT/exit-code"
	run bash "$MONKEY" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"seed 99"* ]]
	[[ "$output" == *"monkey-journey-monkey-ticket-seed-real-stack"* ]]
}

@test "issue-body keeps the issue under GitHub's size limit" {
	recorded 1
	for _ in $(seq 3000); do echo "step 7: uncaught error: a long line of text to fill the issue body"; done \
		>>"$OUT/test-results/monkey-journey-monkey-results-seed-real-stack/monkey.md"
	run bash "$MONKEY" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[ "${#output}" -lt 60000 ]
	[[ "$output" == *"truncated"* ]]
}

# gh answers: the open ci-failure issues as JSON in $GH_ISSUES, labels in $GH_LABELS.
stub_gh() {
	cat >"$GH_STUB_RULES" <<'EOF'
gh_stub() {
	case "$1 $2" in
	"issue list") echo "${GH_ISSUES:-[]}" ;;
	"label list") printf '%s\n' ${GH_LABELS:-} ;;
	"label create" | "issue create" | "issue comment" | "issue close") ;;
	*) return 1 ;;
	esac
}
EOF
}

@test "report on a failed run opens a ci-failure issue" {
	recorded 1
	stub_gh
	GH_LABELS='ci-failure needs-triage' run bash "$MONKEY" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue create --title Monkey runs failing --label ci-failure --label needs-triage --body ' "$GH_STUB_LOG"
	run ! grep -q 'label create' "$GH_STUB_LOG"
}

@test "report creates the labels a repo lacks" {
	recorded 1
	stub_gh
	run bash "$MONKEY" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'label create ci-failure' "$GH_STUB_LOG"
	grep -q 'label create needs-triage --color 1D76DB --description Maintainer needs to evaluate this issue' "$GH_STUB_LOG"
}

@test "report on a failed run comments on the open monkey issue instead of opening another" {
	recorded 1
	stub_gh
	GH_LABELS='ci-failure needs-triage' \
		GH_ISSUES='[{"number": 5, "title": "API fuzz failing as dev-account", "body": "<!-- api-fuzz: dev-account -->"}, {"number": 9, "title": "Monkey runs failing", "body": "<!-- monkey -->"}]' \
		run bash "$MONKEY" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue comment 9 --body ' "$GH_STUB_LOG"
	run ! grep -q 'issue create' "$GH_STUB_LOG"
}

@test "report on a green run closes the open monkey issue only" {
	recorded 0
	stub_gh
	GH_ISSUES='[{"number": 3, "title": "API fuzz failing as dev-account", "body": "<!-- api-fuzz: dev-account -->"}, {"number": 4, "title": "Monkey runs failing", "body": "<!-- monkey -->"}]' \
		run bash "$MONKEY" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue comment 4 --body ' "$GH_STUB_LOG"
	grep -q 'issue close 4' "$GH_STUB_LOG"
	run ! grep -q 'issue close 3' "$GH_STUB_LOG"
}

@test "report on a green run with no open issue changes nothing" {
	recorded 0
	stub_gh
	run bash "$MONKEY" report "$OUT"
	[ "$status" -eq 0 ]
	run ! grep -q 'issue create\|issue comment\|issue close' "$GH_STUB_LOG"
}
