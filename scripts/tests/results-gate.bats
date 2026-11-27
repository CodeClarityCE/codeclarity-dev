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

# One SBOM page row: package@version, ecosystem.
sbom_row() {
	printf '{"name": "%s", "version": "%s", "ecosystem": "%s"}' "${1%@*}" "${1##*@}" "$2"
}

# One licence page row: licence id, then the package@version entries using it.
licence_row() {
	local id=$1 deps
	shift
	deps=$(printf '"%s",' "$@")
	printf '{"id": "%s", "deps_using_license": [%s]}' "$id" "${deps%,}"
}

# Records a finished benchmark run of fixture input $1 in $REC, with page 0 of the vulnerability
# list on stdin; its SBOM and licence lists are empty until record_list rewrites them.
record() {
	[[ -f "$REC/run.tsv" ]] || printf 'name\trepo\tcommit\tsubdir\tanalysis\tworkspaces\n' >"$REC/run.tsv"
	printf '%s\tfixture\t-\t.\tana-%s\t.\n' "$1" "$1" >>"$REC/run.tsv"
	echo "$PIN" >"$REC/knowledge-dump.txt"
	mkdir -p "$REC/$1.pages" "$REC/$1.sbom" "$REC/$1.licences"
	cat >"$REC/$1.pages/0.json"
	page 0 0 >"$REC/$1.sbom/0.json"
	page 0 0 >"$REC/$1.licences/0.json"
}

# Rewrites page 0 of input $1's list $2 (sbom or licences) in $REC from stdin.
record_list() {
	cat >"$REC/$1.$2/0.json"
}

# Writes the expected results of type $2 (vulnerabilities by default) of input $1 from tab-separated
# lines on stdin; the input's other types are expected empty unless written too.
expected() {
	local type=${2:-vulnerabilities} t
	mkdir -p "$RESULTS_GATE_DIR/expected/$1"
	for t in vulnerabilities sbom licences; do
		[[ -f "$RESULTS_GATE_DIR/expected/$1/$t.tsv" ]] || header "$t" >"$RESULTS_GATE_DIR/expected/$1/$t.tsv"
	done
	{
		header "$type"
		cat
	} >"$RESULTS_GATE_DIR/expected/$1/$type.tsv"
}

# Prints the header line of result type $1's expected file.
header() {
	case "$1" in
	vulnerabilities) printf 'workspace\tvulnerability\tpackage\tversion\n' ;;
	sbom) printf 'workspace\tecosystem\tpackage\tversion\n' ;;
	licences) printf 'workspace\tlicence\tpackage\tversion\n' ;;
	esac
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

@test "check fails on an SBOM entry or a licence that appeared or disappeared" {
	expected app sbom <<'EOF2'
.	npm	a	1.0.0
.	npm	b	2.0.0
EOF2
	expected app licences <<'EOF2'
.	MIT	a	1.0.0
EOF2
	page 0 0 | record app
	page 0 1 "$(sbom_row a@1.0.0 npm)" "$(sbom_row @s/c@3.0.0 npm)" | record_list app sbom
	page 0 1 "$(licence_row MIT a@1.0.0)" "$(licence_row ISC @s/c@3.0.0)" | record_list app licences
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app vulnerabilities: 0 as expected"* ]]
	[[ "$output" == *"app sbom: 1 appeared, 1 disappeared"* ]]
	[[ "$output" == *"  appeared:    .  npm  @s/c  3.0.0"* ]]
	[[ "$output" == *"  disappeared: .  npm  b  2.0.0"* ]]
	[[ "$output" == *"app licences: 1 appeared, 0 disappeared"* ]]
	[[ "$output" == *"  appeared:    .  ISC  @s/c  3.0.0"* ]]
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
	expected app sbom <<'EOF2'
api	npm	a	1.0.0
frontend	npm	b	2.0.0
EOF2
	expected app licences <<'EOF2'
api	MIT	a	1.0.0
frontend	MIT	b	2.0.0
EOF2
	mkdir -p "$REC/app.pages" "$REC/app.sbom" "$REC/app.licences"
	page 0 1 "$(row CVE-1 a@1.0.0)" >"$REC/app.pages/api-0.json"
	page 0 2 "$(row CVE-2 b@2.0.0)" >"$REC/app.pages/frontend-0.json"
	page 1 2 "$(row CVE-3 c@3.0.0)" >"$REC/app.pages/frontend-1.json"
	page 0 1 "$(sbom_row a@1.0.0 npm)" >"$REC/app.sbom/api-0.json"
	page 0 2 >"$REC/app.sbom/frontend-0.json"
	page 1 2 "$(sbom_row b@2.0.0 npm)" >"$REC/app.sbom/frontend-1.json"
	page 0 1 "$(licence_row MIT a@1.0.0)" >"$REC/app.licences/api-0.json"
	page 0 1 "$(licence_row MIT b@2.0.0)" >"$REC/app.licences/frontend-0.json"
	run sh "$GATE" check "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"app sbom: 2 as expected"* ]]
	[[ "$output" == *"app licences: 2 as expected"* ]]
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

@test "check fails on a run that did not record a result type's list" {
	expected app </dev/null
	page 0 0 | record app
	rm -r "$REC/app.licences"
	run sh "$GATE" check "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app: no licences list in the recorded run"* ]]
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
	"GET /org/org1/projects/proj1/analysis/ana1/sbom" | "GET /org/org1/projects/proj1/analysis/ana1/licenses")
		local n=${2##*page=} list=sbom
		[[ "$path" != *licenses* ]] || list=licences
		# An empty list unless the test wrote its pages.
		cat "$BATS_TEST_TMPDIR/$list/${n%%&*}.json" 2>/dev/null ||
			echo '{"data": [], "page": 0, "total_pages": 0}' ;;
	*) echo "unexpected: $*" >&2; return 22 ;;
	esac
}
RULES
	: >"$CURL_STUB_LOG"
}

@test "run analyses only the gate's inputs and fails on a finding that appeared" {
	fake_stack
	fake_db
	expected app <<'EOF2'
.	CVE-1	a	1.0.0
EOF2
	page 0 1 "$(row CVE-1 a@1.0.0)" "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	mkdir -p "$BATS_TEST_TMPDIR/sbom"
	page 0 1 "$(sbom_row a@1.0.0 npm)" >"$BATS_TEST_TMPDIR/sbom/0.json"
	run sh "$GATE" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app vulnerabilities: 1 appeared, 0 disappeared"* ]]
	[[ "$output" == *"  appeared:    .  CVE-2  b  2.0.0"* ]]
	[[ "$output" == *"app sbom: 1 appeared, 0 disappeared"* ]]
	[[ "$output" == *"app licences: 0 as expected"* ]]
	# One analysis: "other" is a benchmark input but not a gate input.
	[ "$(grep -c '^POST .*/analyses$' "$CURL_STUB_LOG")" = 1 ]
	[ "$(cut -f1 "$REC/run.tsv" | tail -n +2)" = app ]
}

@test "update with no recorded run analyses the inputs and writes their findings" {
	fake_stack
	fake_db
	page 0 1 "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	run sh "$GATE" update
	[ "$status" -eq 0 ]
	[ "$(tail -n +2 "$RESULTS_GATE_DIR/expected/app/vulnerabilities.tsv")" = '.	CVE-2	b	2.0.0' ]
}

@test "the committed gate inputs are benchmark inputs, each with expected results" {
	local dir="$BATS_TEST_DIRNAME/../results-gate" name type
	grep -qv -e '^#' -e '^$' "$dir/inputs.txt"
	grep -v -e '^#' -e '^$' "$dir/inputs.txt" | while IFS= read -r name; do
		cut -f1 "$BATS_TEST_DIRNAME/../benchmark/inputs.tsv" | grep -qx "$name"
		for type in vulnerabilities sbom licences; do
			[ -f "$dir/expected/$name/$type.tsv" ]
			# Stored as update writes it: the header, then sorted unique lines.
			[ "$(head -n 1 "$dir/expected/$name/$type.tsv")" = "$(header "$type")" ]
			tail -n +2 "$dir/expected/$name/$type.tsv" | LC_ALL=C sort -cu
		done
	done
}

@test "the committed registry rows cover every package of the expected SBOM entries" {
	# Versions can be missing: the follower skips prereleases such as 1.0.0-next.29.
	local dir="$BATS_TEST_DIRNAME/../results-gate" eco name lang file
	while IFS=$'\t' read -r _ eco name _; do
		case "$eco" in npm) lang=javascript ;; packagist) lang=php ;; *) lang=$eco ;; esac
		file="$dir/registry/$lang/$name.json"
		jq -e --arg n "$name" --arg l "$lang" '.name == $n and .language == $l' "$file" >/dev/null || {
			echo "no recorded row for $lang $name in $file"
			return 1
		}
	done < <(tail -q -n +2 "$dir"/expected/*/sbom.tsv)
}

@test "the committed gate inputs cover every lockfile the analyzers read" {
	local dir="$BATS_TEST_DIRNAME/../results-gate" fixtures="$BATS_TEST_DIRNAME/../benchmark/fixtures" lock name found
	for lock in package-lock.json yarn.lock pnpm-lock.yaml composer.lock; do
		found=
		while IFS= read -r name; do
			[[ ! -f "$fixtures/$name/$lock.fixture" ]] || found=$name
		done < <(grep -v -e '^#' -e '^$' "$dir/inputs.txt")
		[[ -n "$found" ]] || {
			echo "no gate input has a $lock"
			return 1
		}
	done
}

# A stand-in for the stack's knowledge database (RESULTS_GATE_PSQL): logs each query's first line
# to the curl log, so the order of queries and API calls shows, and answers from the test's files.
fake_db() {
	export RESULTS_GATE_PSQL="$BATS_TEST_TMPDIR/psql"
	cat >"$RESULTS_GATE_PSQL" <<'STUB'
#!/usr/bin/env bash
sql=$(cat)
echo "SQL ${sql%%$'\n'*}" >>"$CURL_STUB_LOG"
echo "$sql" >>"$BATS_TEST_TMPDIR/sql.log"
case "$sql" in
"-- load"*) echo 1795780000.123456 ;;
"-- fetched"*) cat "$BATS_TEST_TMPDIR/fetched" 2>/dev/null || : ;;
"-- export"*) cat "$BATS_TEST_TMPDIR/rows" ;;
"-- clear"*) ;;
*)
	echo "unexpected query: $sql" >&2
	exit 1
	;;
esac
STUB
	chmod +x "$RESULTS_GATE_PSQL"
	mkdir -p "$RESULTS_GATE_DIR/registry/javascript"
	echo '{"name": "a", "language": "javascript", "versions": [{"version": "1.0.0"}]}' >"$RESULTS_GATE_DIR/registry/javascript/a.json"
}

# The stand-in API's SBOM list for input app: package a@1.0.0 from npm.
sbom_a() {
	page 0 0 >"$BATS_TEST_TMPDIR/pages/0.json"
	mkdir -p "$BATS_TEST_TMPDIR/sbom"
	page 0 1 "$(sbom_row a@1.0.0 npm)" >"$BATS_TEST_TMPDIR/sbom/0.json"
	expected app sbom <<<'.	npm	a	1.0.0'
}

# Prints the line number of the first line of the curl log that matches $1.
logged_at() {
	grep -m1 -n -e "$1" "$CURL_STUB_LOG" | cut -d: -f1
}

@test "run loads the recorded registry rows before it analyses the inputs" {
	fake_stack
	fake_db
	sbom_a
	run sh "$GATE" run --out "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"loaded the recorded registry rows of 1 package"* ]]
	[ "$(logged_at '^SQL -- load')" -lt "$(logged_at '^POST .*/analyses$')" ]
	grep -q '"name":"a"' "$BATS_TEST_TMPDIR/sql.log"
}

@test "run fails, naming the package, when the follower fetched one from a live registry" {
	fake_stack
	fake_db
	sbom_a
	echo 'javascript a (fetched from the registry)' >"$BATS_TEST_TMPDIR/fetched"
	run sh "$GATE" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"  javascript a (fetched from the registry)"* ]]
	[[ "$output" == *"gate.sh record"* ]]
	[[ "$output" != *"as expected"* ]]
	# It asks about the packages of the run's SBOM, after the analyses.
	grep -q '"name":"a","language":"javascript"' "$BATS_TEST_TMPDIR/sql.log"
	[ "$(logged_at '^SQL -- fetched')" -gt "$(logged_at '^POST .*/analyses$')" ]
}

@test "run refuses to analyse anything without recorded registry rows" {
	fake_stack
	fake_db
	sbom_a
	rm -r "$RESULTS_GATE_DIR/registry"
	run sh "$GATE" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no recorded registry rows"*"gate.sh record"* ]]
	[ "$(grep -c '/analyses$' "$CURL_STUB_LOG")" = 0 ]
}

@test "record with a recorded run writes the stack's rows of its packages, one file each" {
	fake_stack
	fake_db
	expected app </dev/null
	page 0 0 | record app
	page 0 1 "$(sbom_row @s/b@2.0.0 npm)" "$(sbom_row v/c@1.0.0 packagist)" | record_list app sbom
	cat >"$BATS_TEST_TMPDIR/rows" <<'EOF2'
{"name": "@s/b", "language": "javascript", "versions": [{"version": "2.0.0"}], "license": "MIT"}
{"name": "v/c", "language": "php", "versions": [], "license": "LGPL-3.0", "description": "one\ntwo"}
EOF2
	run sh "$GATE" record "$REC"
	[ "$status" -eq 0 ]
	# The old recording is gone; each file holds one package, its keys sorted.
	[ ! -e "$RESULTS_GATE_DIR/registry/javascript/a.json" ]
	[ "$(jq -c . "$RESULTS_GATE_DIR/registry/javascript/@s/b.json")" = \
		'{"language":"javascript","license":"MIT","name":"@s/b","versions":[{"version":"2.0.0"}]}' ]
	[ "$(jq -r .license "$RESULTS_GATE_DIR/registry/php/v/c.json")" = LGPL-3.0 ]
	# A JSON escape comes through as it was.
	[ "$(jq -c .description "$RESULTS_GATE_DIR/registry/php/v/c.json")" = '"one\ntwo"' ]
	grep -q '"name":"v/c","language":"php"' "$BATS_TEST_TMPDIR/sql.log"
	[[ "$output" == *"recorded the registry rows of 2 package(s)"* ]]
}

@test "record fails when the stack has no row for a package of the run" {
	fake_stack
	fake_db
	expected app </dev/null
	page 0 0 | record app
	page 0 1 "$(sbom_row a@1.0.0 npm)" "$(sbom_row b@2.0.0 npm)" | record_list app sbom
	echo '{"name": "a", "language": "javascript", "versions": []}' >"$BATS_TEST_TMPDIR/rows"
	run sh "$GATE" record "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"javascript b: no row in the knowledge database"* ]]
	# The recording is left as it was.
	[ -f "$RESULTS_GATE_DIR/registry/javascript/a.json" ]
}

@test "record with no recorded run clears the packages' rows and analyses on live registries" {
	fake_stack
	fake_db
	sbom_a
	echo '{"name": "a", "language": "javascript", "versions": [{"version": "1.0.0"}]}' >"$BATS_TEST_TMPDIR/rows"
	run sh "$GATE" record
	[ "$status" -eq 0 ]
	[ "$(logged_at '^SQL -- clear')" -lt "$(logged_at '^POST .*/analyses$')" ]
	[ -z "$(logged_at '^SQL -- load')" ]
	[ "$(logged_at '^SQL -- export')" -gt "$(logged_at '^POST .*/analyses$')" ]
	[ -f "$RESULTS_GATE_DIR/registry/javascript/a.json" ]
	# Then compares the run's findings, so a changed finding shows next to the new rows.
	[[ "$output" == *"app sbom: 1 as expected"* ]]
}
