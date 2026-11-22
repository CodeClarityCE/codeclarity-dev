#!/usr/bin/env bats
# Tests scripts/results-gate/gate.sh: comparing recorded runs with the expected results,
# regenerating them, and a run against a stand-in API (curl is the stub in stubs/). No Docker or network.
# Run from the repo root: bats scripts/tests

GATE="$BATS_TEST_DIRNAME/../results-gate/gate.sh"
PIN='codeclarityce/knowledge-dump:2026-11-16@sha256:aaaa'

setup() {
	export RESULTS_GATE_DIR="$BATS_TEST_TMPDIR/gate"
	export BENCHMARK_DIR="$BATS_TEST_TMPDIR/benchmark"
	REC="$BATS_TEST_TMPDIR/rec"
	mkdir -p "$RESULTS_GATE_DIR/expected" "$BENCHMARK_DIR" "$REC"
	echo "$PIN" >"$BENCHMARK_DIR/knowledge-dump.txt"
	echo app >"$RESULTS_GATE_DIR/inputs.txt"
}

# One list row as the vulnerabilities endpoint returns it: id, then package@version pairs.
row() {
	local id=$1 affected=() pv
	shift
	for pv; do affected+=("{\"AffectedDependency\": \"${pv%@*}\", \"AffectedVersion\": \"${pv##*@}\"}"); done
	printf '{"Vulnerability": "%s", "Affected": [%s]}' "$id" "$(IFS=,; echo "${affected[*]}")"
}

# One page of the list: page number, total pages, rows.
page() {
	local n=$1 total=$2
	shift 2
	printf '{"data": [%s], "page": %s, "total_pages": %s}\n' "$(IFS=,; echo "$*")" "$n" "$total"
}

# Records a finished benchmark run of fixture input $1 in $REC, with page 0 of the list on stdin.
record() {
	[[ -f "$REC/run.tsv" ]] || printf 'name\trepo\tcommit\tsubdir\tanalysis\tworkspaces\n' >"$REC/run.tsv"
	printf '%s\tfixture\t-\t.\tana-%s\t.\n' "$1" "$1" >>"$REC/run.tsv"
	echo "$PIN" >"$REC/knowledge-dump.txt"
	mkdir -p "$REC/$1.pages"
	cat >"$REC/$1.pages/0.json"
}

# Writes the expected vulnerability instances of input $1 from tab-separated lines on stdin.
expected() {
	mkdir -p "$RESULTS_GATE_DIR/expected/$1"
	{
		printf 'workspace\tvulnerability\tpackage\tversion\n'
		cat
	} >"$RESULTS_GATE_DIR/expected/$1/vulnerabilities.tsv"
}

@test "check passes when the run shows exactly the expected findings" {
	expected app <<'EOF'
.	CVE-1	a	1.0.0
.	CVE-2	b	2.0.0
EOF
	page 0 1 "$(row CVE-2 b@2.0.0)" "$(row CVE-1 a@1.0.0)" | record app
	run sh "$GATE" check "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"app vulnerabilities: 2 as expected"* ]]
}

@test "check fails on a difference and names each finding that appeared or disappeared" {
	expected app <<'EOF2'
.	CVE-1	a	1.0.0
.	CVE-2	b	2.0.0
EOF2
	page 0 1 "$(row CVE-1 a@1.0.0)" "$(row CVE-3 c@3.0.0 c@3.1.0)" | record app
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app vulnerabilities: 2 appeared, 1 disappeared"* ]]
	[[ "$output" == *"  appeared:    .  CVE-3  c  3.0.0"* ]]
	[[ "$output" == *"  appeared:    .  CVE-3  c  3.1.0"* ]]
	[[ "$output" == *"  disappeared: .  CVE-2  b  2.0.0"* ]]
	[[ "$output" != *"CVE-1"* ]]
	[[ "$output" == *"gate.sh update"* ]]
}

@test "update writes each input's findings, sorted, and check then passes" {
	page 0 1 "$(row CVE-2 b@2.0.0)" "$(row CVE-10 a@1.0.0 a@1.0.0)" "$(row CVE-1 a@1.0.0)" | record app
	run sh "$GATE" update "$REC"
	[ "$status" -eq 0 ]
	[ "$(cat "$RESULTS_GATE_DIR/expected/app/vulnerabilities.tsv")" = "$(printf '%s\n' \
		'workspace	vulnerability	package	version' \
		'.	CVE-1	a	1.0.0' \
		'.	CVE-10	a	1.0.0' \
		'.	CVE-2	b	2.0.0')" ]
	run sh "$GATE" check "$REC"
	[ "$status" -eq 0 ]
}

@test "update writes the header alone for an input with no findings" {
	page 0 0 | record app
	run sh "$GATE" update "$REC"
	[ "$status" -eq 0 ]
	[ "$(cat "$RESULTS_GATE_DIR/expected/app/vulnerabilities.tsv")" = 'workspace	vulnerability	package	version' ]
}

@test "check reads every page and each workspace of the run" {
	expected app <<'EOF2'
api	CVE-1	a	1.0.0
frontend	CVE-2	b	2.0.0
frontend	CVE-3	c	3.0.0
EOF2
	printf 'name\trepo\tcommit\tsubdir\tanalysis\tworkspaces\napp\t.\tabc\t.\tana\tapi,frontend\n' >"$REC/run.tsv"
	echo "$PIN" >"$REC/knowledge-dump.txt"
	mkdir -p "$REC/app.pages"
	page 0 1 "$(row CVE-1 a@1.0.0)" >"$REC/app.pages/api-0.json"
	page 0 2 "$(row CVE-2 b@2.0.0)" >"$REC/app.pages/frontend-0.json"
	page 1 2 "$(row CVE-3 c@3.0.0)" >"$REC/app.pages/frontend-1.json"
	run sh "$GATE" check "$REC"
	[ "$status" -eq 0 ]
}

@test "check fails when an input has no expected results, or the run left it out" {
	page 0 0 | record app
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app: no expected results"*"gate.sh update"* ]]
	expected app </dev/null
	echo other >>"$RESULTS_GATE_DIR/inputs.txt"
	expected other </dev/null
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"other: not in the recorded run"* ]]
}

@test "check refuses a run on another knowledge dump than the pinned one" {
	expected app </dev/null
	page 0 0 | record app
	echo 'codeclarityce/knowledge-dump:2027-01-01@sha256:bbbb' >"$REC/knowledge-dump.txt"
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pinned to $PIN"* ]]
	run sh "$GATE" update "$REC"
	[ "$status" -eq 1 ]
}

# A stand-in API for the benchmark runner: one personal org, analyses that complete at once,
# and the list pages in $BATS_TEST_TMPDIR/pages/<page>.json; input "app" is a fixture folder.
fake_stack() {
	export BENCHMARK_ROOT="$BATS_TEST_TMPDIR/root"
	export CURL_STUB_LOG="$BATS_TEST_TMPDIR/curl.log"
	export CURL_STUB_RULES="$BATS_TEST_TMPDIR/curl-rules.bash"
	export BATS_TEST_TMPDIR ANALYSIS_POLL_SECONDS=0 LOGIN_WAIT_SECONDS=0
	PATH="$BATS_TEST_DIRNAME/stubs:$PATH"
	mkdir -p "$BENCHMARK_ROOT/.cloud/docker" "$BENCHMARK_DIR/fixtures/app" "$BENCHMARK_DIR/ground-truth" "$BATS_TEST_TMPDIR/pages"
	# shellcheck disable=SC2016 # the Compose line, unexpanded
	printf '    image: ${KNOWLEDGE_DUMP_IMAGE:-%s}\n' "$PIN" >"$BENCHMARK_ROOT/.cloud/docker/docker-compose.yaml"
	echo '{"name": "app"}' >"$BENCHMARK_DIR/fixtures/app/package.json.fixture"
	printf 'name\trepo\tcommit\tsubdir\tworkspaces\napp\tfixture\t-\t.\t.\nother\tfixture\t-\t.\t.\n' >"$BENCHMARK_DIR/inputs.tsv"
	printf 'vulnerability\tpackage\tversion\tverdict\tcause\tevidence\n' >"$BENCHMARK_DIR/ground-truth/app.tsv"
	cat >"$CURL_STUB_RULES" <<'RULES'
curl_stub() {
	local path=${2#*://*/}
	case "$1 /${path%%\?*}" in
	"POST /auth/authenticate") echo '{"data": {"token": "t0k"}}' ;;
	"GET /org") echo '{"data": [{"organization": {"id": "org1", "personal": true}}]}' ;;
	"POST /org/org1/projects") echo '{"id": "proj1"}' ;;
	"PATCH /org/org1/file/proj1/upload") echo '{}' ;;
	"GET /org/org1/analyzers") echo '{"data": [{"id": "an1", "name": "Default Analyzer"}]}' ;;
	"POST /org/org1/projects/proj1/analyses") echo '{"id": "ana1"}' ;;
	"GET /org/org1/projects/proj1/analyses/ana1")
		echo '{"data": {"status": "completed", "steps": [[{"Name": "js-sbom", "Status": "success"}]]}}' ;;
	"GET /org/org1/projects/proj1/analysis/ana1/vulnerabilities/knowledge-snapshot") echo '{"data": null}' ;;
	"GET /org/org1/projects/proj1/analysis/ana1/vulnerabilities")
		local n=${2##*page=}
		cat "$BATS_TEST_TMPDIR/pages/${n%%&*}.json" ;;
	*) echo "unexpected: $*" >&2; return 22 ;;
	esac
}
RULES
	: >"$CURL_STUB_LOG"
}

@test "run analyses only the gate's inputs and fails on a finding that appeared" {
	fake_stack
	expected app <<'EOF2'
.	CVE-1	a	1.0.0
EOF2
	page 0 1 "$(row CVE-1 a@1.0.0)" "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	run sh "$GATE" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app vulnerabilities: 1 appeared, 0 disappeared"* ]]
	[[ "$output" == *"  appeared:    .  CVE-2  b  2.0.0"* ]]
	# One analysis: "other" is a benchmark input but not a gate input.
	[ "$(grep -c '^POST .*/analyses$' "$CURL_STUB_LOG")" = 1 ]
	[ "$(cut -f1 "$REC/run.tsv" | tail -n +2)" = app ]
}

@test "update with no recorded run analyses the inputs and writes their findings" {
	fake_stack
	page 0 1 "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	run sh "$GATE" update
	[ "$status" -eq 0 ]
	[ "$(tail -n +2 "$RESULTS_GATE_DIR/expected/app/vulnerabilities.tsv")" = '.	CVE-2	b	2.0.0' ]
}

@test "the committed gate inputs are benchmark inputs, each with expected results" {
	local dir="$BATS_TEST_DIRNAME/../results-gate" name
	grep -qv -e '^#' -e '^$' "$dir/inputs.txt"
	grep -v -e '^#' -e '^$' "$dir/inputs.txt" | while IFS= read -r name; do
		cut -f1 "$BATS_TEST_DIRNAME/../benchmark/inputs.tsv" | grep -qx "$name"
		[ -f "$dir/expected/$name/vulnerabilities.tsv" ]
		# Stored as update writes it: the header, then sorted unique lines.
		[ "$(head -n 1 "$dir/expected/$name/vulnerabilities.tsv")" = 'workspace	vulnerability	package	version' ]
		tail -n +2 "$dir/expected/$name/vulnerabilities.tsv" | LC_ALL=C sort -cu
	done
}
