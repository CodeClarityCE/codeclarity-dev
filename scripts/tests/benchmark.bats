#!/usr/bin/env bats
# Tests scripts/benchmark/benchmark.sh: argument handling, the report on recorded API responses,
# and a run against a stand-in API (curl is the stub in stubs/). No Docker or network.
# Run from the repo root: bats scripts/tests

BENCHMARK="$BATS_TEST_DIRNAME/../benchmark/benchmark.sh"
FIXTURES="$BATS_TEST_DIRNAME/fixtures/benchmark"
PIN='codeclarityce/knowledge-dump:2026-11-16@sha256:aaaa'

setup() {
	export BENCHMARK_DIR="$BATS_TEST_TMPDIR/benchmark"
	export BENCHMARK_ROOT="$BATS_TEST_TMPDIR/root"
	export CURL_STUB_LOG="$BATS_TEST_TMPDIR/curl.log"
	export CURL_STUB_RULES="$BATS_TEST_TMPDIR/curl-rules.bash"
	export BATS_TEST_TMPDIR
	export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$BATS_TEST_TMPDIR/gitconfig"
	export ANALYSIS_POLL_SECONDS=0 LOGIN_WAIT_SECONDS=0
	PATH="$BATS_TEST_DIRNAME/stubs:$PATH"
	REC="$BATS_TEST_TMPDIR/rec"
	mkdir -p "$BENCHMARK_DIR/ground-truth" "$BENCHMARK_ROOT/.cloud/docker" "$REC"
	: >"$CURL_STUB_LOG"
	echo "$PIN" >"$BENCHMARK_DIR/knowledge-dump.txt"
	# shellcheck disable=SC2016 # the Compose line, unexpanded
	printf '    image: ${KNOWLEDGE_DUMP_IMAGE:-%s}\n' "$PIN" >"$BENCHMARK_ROOT/.cloud/docker/docker-compose.yaml"
}

# Writes the ground truth of input $1 from tab-separated lines on stdin.
ground_truth() {
	{
		printf 'vulnerability\tpackage\tversion\tverdict\tcause\tevidence\n'
		cat
	} >"$BENCHMARK_DIR/ground-truth/$1.tsv"
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

# Records a finished run of input $1 (repo $2, commit $3, analysis $4) in $REC, with page 0 on stdin.
record() {
	[[ -f "$REC/run.tsv" ]] || printf 'name\trepo\tcommit\tsubdir\tanalysis\n' >"$REC/run.tsv"
	printf '%s\t%s\t%s\t.\t%s\n' "$1" "$2" "$3" "$4" >>"$REC/run.tsv"
	echo "$PIN" >"$REC/knowledge-dump.txt"
	mkdir -p "$REC/$1.pages"
	cat >"$REC/$1.pages/0.json"
	echo '{"data": {"sources": [{"source": "osv", "watermark": "2026-11-16T03:00:00Z"}, {"source": "nvd", "watermark": null}]}}' >"$REC/$1.knowledge.json"
}

# Prints the output with runs of spaces squeezed, so table rows compare without column padding.
squeezed() {
	tr -s ' ' <<<"$output"
}

# A ground truth with each verdict, and a run that shows some of it plus one unjudged instance.
mixed_input() {
	ground_truth app <<'EOF'
CVE-1	a	1.0.0	TP	-	https://github.com/advisories/GHSA-1
CVE-2	b	2.0.0	TP	-	https://github.com/advisories/GHSA-2
CVE-3	c	1.0.0	FP	gcve-name-collision	https://vulnerability.circl.lu/vuln/CVE-3
CVE-4	d	1.0.0	FP	no-veto-coarse-range	https://github.com/advisories?query=CVE-4
CVE-5	e	1.0.0	LAG	withdrawn-after-snapshot	https://github.com/advisories?query=CVE-5
CVE-6	f	1.0.0	LAG	published-after-snapshot	https://github.com/advisories/GHSA-6
CVE-7	g	1.0.0	TP	-	https://github.com/advisories/GHSA-7
CVE-8	h	1.0.0	FP	gcve-name-collision	https://vulnerability.circl.lu/vuln/CVE-8
EOF
	page 0 1 "$(row CVE-1 a@1.0.0)" "$(row CVE-3 c@1.0.0)" "$(row CVE-5 e@1.0.0)" \
		"$(row CVE-7 g@1.0.0)" "$(row CVE-8 h@1.0.0)" "$(row CVE-9 z@9.9.9)" |
		record app apprepo 0123456789abcdef0123 analysis-1
}

@test "with no command it prints usage and exits 2" {
	run sh "$BENCHMARK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
}

@test "an unknown command or option exits 2 with usage" {
	run sh "$BENCHMARK" frobnicate
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
	run sh "$BENCHMARK" run --bogus
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
}

@test "--help prints usage and exits 0" {
	run sh "$BENCHMARK" --help
	[ "$status" -eq 0 ]
	[[ "$output" == *"usage:"* ]]
}

@test "report needs a directory holding a recorded run" {
	run sh "$BENCHMARK" report
	[ "$status" -eq 2 ]
	run sh "$BENCHMARK" report "$BATS_TEST_TMPDIR/nothing"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no recorded run"* ]]
}

@test "the report counts shown instances against the ground truth, with precision and recall" {
	mixed_input
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	out=$(squeezed)
	[[ "$out" == *"Input Shown Correct Wrong Unjudged Expected Found Missed Precision Recall"* ]]
	[[ "$out" == *"app 6 3 2 1 4 3 1 60.0% 75.0%"* ]]
	[[ "$out" == *"total 6 3 2 1 4 3 1 60.0% 75.0%"* ]]
}

@test "the report lists wrong and missed instances by cause, and unjudged ones" {
	mixed_input
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	out=$(squeezed)
	[[ "$out" == *"Wrong (shown, but false), by cause:
 gcve-name-collision: 2
 app CVE-3 c@1.0.0
 app CVE-8 h@1.0.0

Missed (true, but not shown), by cause:
 untagged: 1
 app CVE-2 b@2.0.0

Unjudged (shown, but not in the ground truth):
 app CVE-9 z@9.9.9"* ]]
}

@test "the report names the knowledge dump, the input commits and the source watermarks" {
	mixed_input
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"Knowledge dump: $PIN"* ]]
	[[ "$output" == *"app: apprepo at 0123456789abcdef0123, analysis analysis-1"* ]]
	[[ "$output" == *"knowledge: osv 2026-11-16T03:00:00Z, nvd none"* ]]
}

@test "a ground-truth instance listed twice for one version counts once" {
	ground_truth app <<'EOF'
CVE-1	a	1.0.0	TP	-	https://github.com/advisories/GHSA-1
EOF
	page 0 1 "$(row CVE-1 a@1.0.0 a@1.0.0)" | record app apprepo abc analysis-1
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	[[ "$(squeezed)" == *"app 1 1 0 0 1 1 0 100.0% 100.0%"* ]]
}

@test "a run with nothing shown or expected reports n/a" {
	ground_truth app </dev/null
	page 0 0 | record app apprepo abc analysis-1
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	[[ "$(squeezed)" == *"app 0 0 0 0 0 0 0 n/a n/a"* ]]
}

@test "a ground truth with an unknown verdict is refused" {
	ground_truth app <<'EOF'
CVE-1	a	1.0.0	MAYBE	-	https://github.com/advisories/GHSA-1
EOF
	page 0 1 | record app apprepo abc analysis-1
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"CVE-1"*"MAYBE"* ]]
}

@test "the 2026-11-18 measurement reproduces 19 wrong of 128 shown" {
	cp "$BATS_TEST_DIRNAME"/../benchmark/ground-truth/*.tsv "$BENCHMARK_DIR/ground-truth/"
	record cc-frontend frontend 9f01be4392114ccbb4259782b0f6e3ea2a6817a0 a-frontend <"$FIXTURES/cc-frontend.json"
	record cc-api api f40a6f418ce92cefcd257fda048a6c236b2900ee a-api <"$FIXTURES/cc-api.json"
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	out=$(squeezed)
	[[ "$out" == *"cc-frontend 52 44 8 0 44 44 0 84.6% 100.0%"* ]]
	[[ "$out" == *"cc-api 76 65 11 0 65 65 0 85.5% 100.0%"* ]]
	[[ "$out" == *"total 128 109 19 0 109 109 0 85.2% 100.0%"* ]]
}

# A git repo at $BENCHMARK_ROOT/apprepo with one npm project commit, listed as input "app".
app_input() {
	local repo="$BENCHMARK_ROOT/apprepo"
	mkdir -p "$repo/web"
	git -C "$repo" init -q
	echo '{"name": "app"}' >"$repo/web/package.json"
	git -C "$repo" add web
	git -C "$repo" -c user.name=Test -c user.email=test@example.invalid commit -q -m "Add app"
	APP_COMMIT=$(git -C "$repo" rev-parse HEAD)
	printf 'name\trepo\tcommit\tsubdir\napp\tapprepo\t%s\tweb\nother\tapprepo\t%s\t.\n' "$APP_COMMIT" "$APP_COMMIT" \
		>"$BENCHMARK_DIR/inputs.tsv"
}

# A stand-in API: one personal org, the Default Analyzer, analyses that complete at once,
# and the list pages in $BATS_TEST_TMPDIR/pages/<page>.json.
fake_api() {
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
	"GET /org/org1/projects/proj1/analysis/ana1/vulnerabilities/knowledge-snapshot")
		echo '{"data": {"sources": [{"source": "osv", "watermark": "2026-11-16T03:00:00Z"}]}}' ;;
	"GET /org/org1/projects/proj1/analysis/ana1/vulnerabilities/vulnerability/"*)
		local id=${path##*/vulnerability/}
		cat "$BATS_TEST_TMPDIR/details/${id%%\?*}.json" ;;
	"GET /org/org1/projects/proj1/analysis/ana1/vulnerabilities")
		local n=${2##*page=}
		cat "$BATS_TEST_TMPDIR/pages/${n%%&*}.json" ;;
	*) echo "unexpected: $*" >&2; return 22 ;;
	esac
}
RULES
	mkdir -p "$BATS_TEST_TMPDIR/pages"
}

@test "run analyses an input at its pinned commit and reports every page of the list" {
	app_input
	fake_api
	ground_truth app <<'EOF'
CVE-1	a	1.0.0	TP	-	https://github.com/advisories/GHSA-1
CVE-2	b	2.0.0	FP	gcve-name-collision	https://vulnerability.circl.lu/vuln/CVE-2
EOF
	page 0 2 "$(row CVE-1 a@1.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	page 1 2 "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/1.json"
	run sh "$BENCHMARK" run --input app --out "$REC"
	[ "$status" -eq 0 ]
	[[ "$(squeezed)" == *"app 2 1 1 0 1 1 0 50.0% 100.0%"* ]]
	[[ "$output" == *"app: apprepo/web at $APP_COMMIT, analysis ana1"* ]]
	grep -qx "GET http://localhost:3000/org/org1/projects/proj1/analysis/ana1/vulnerabilities?workspace=.&entries_per_page=100&page=0" "$CURL_STUB_LOG"
	grep -qx "GET http://localhost:3000/org/org1/projects/proj1/analysis/ana1/vulnerabilities?workspace=.&entries_per_page=100&page=1" "$CURL_STUB_LOG"
	[ "$(grep -c 'page=2' "$CURL_STUB_LOG")" = 0 ]
	grep -q '^PATCH .*/upload$' "$CURL_STUB_LOG"
	# The upload holds the input's subdir at the archive root.
	tar -tzf "$REC/app.tar.gz" | grep -qx 'package.json'
	# The recorded run reports the same again offline.
	run sh "$BENCHMARK" report "$REC"
	[[ "$(squeezed)" == *"app 2 1 1 0 1 1 0 50.0% 100.0%"* ]]
}

# A repo at $BENCHMARK_ROOT/umbrella whose api and frontend folders are submodules, listed as
# input "mono" reading those two workspaces.
mono_input() {
	local repo="$BENCHMARK_ROOT/umbrella" sub sha
	mkdir -p "$repo"
	git -C "$repo" init -q
	echo '{"private": true}' >"$repo/package.json"
	for sub in api frontend; do
		mkdir -p "$repo/$sub"
		git -C "$repo/$sub" init -q
		echo "{\"name\": \"$sub\"}" >"$repo/$sub/package.json"
		git -C "$repo/$sub" add package.json
		git -C "$repo/$sub" -c user.name=Test -c user.email=test@example.invalid commit -q -m "Add $sub"
		sha=$(git -C "$repo/$sub" rev-parse HEAD)
		git -C "$repo" update-index --add --cacheinfo "160000,$sha,$sub"
	done
	git -C "$repo" add package.json
	git -C "$repo" -c user.name=Test -c user.email=test@example.invalid commit -q -m "Add submodules"
	printf 'name\trepo\tcommit\tsubdir\tworkspaces\nmono\tumbrella\t%s\t.\tapi,frontend\n' "$(git -C "$repo" rev-parse HEAD)" \
		>"$BENCHMARK_DIR/inputs.tsv"
}

@test "run archives an input's submodules and reads each listed workspace" {
	mono_input
	fake_api
	ground_truth mono <<'EOF'
CVE-1	a	1.0.0	TP	-	https://github.com/advisories/GHSA-1
CVE-2	b	2.0.0	TP	-	https://github.com/advisories/GHSA-2
EOF
	# Both workspaces get the same list pages from the stand-in API.
	page 0 1 "$(row CVE-1 a@1.0.0)" "$(row CVE-2 b@2.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	run sh "$BENCHMARK" run --out "$REC"
	[ "$status" -eq 0 ]
	tar -tzf "$REC/mono.tar.gz" | sed 's#^\./##' >"$BATS_TEST_TMPDIR/listing"
	grep -qx 'package.json' "$BATS_TEST_TMPDIR/listing"
	grep -qx 'api/package.json' "$BATS_TEST_TMPDIR/listing"
	grep -qx 'frontend/package.json' "$BATS_TEST_TMPDIR/listing"
	grep -q 'vulnerabilities?workspace=api&entries_per_page=100&page=0$' "$CURL_STUB_LOG"
	grep -q 'vulnerabilities?workspace=frontend&entries_per_page=100&page=0$' "$CURL_STUB_LOG"
	[ "$(grep -c 'workspace=\.&' "$CURL_STUB_LOG")" = 0 ]
	# An instance shown in both workspaces counts once.
	[[ "$(squeezed)" == *"mono 2 2 0 0 2 2 0 100.0% 100.0%"* ]]
	[[ "$output" == *"mono: umbrella at "*", workspaces api, frontend, analysis ana1"* ]]
}

@test "run refuses an input name that is not in the inputs file" {
	app_input
	run sh "$BENCHMARK" run --input nope --out "$REC"
	[ "$status" -eq 2 ]
	[[ "$output" == *"unknown input: nope"* ]]
	[ ! -s "$CURL_STUB_LOG" ]
}

@test "run refuses a stack that restores another knowledge dump than the pinned one" {
	app_input
	# shellcheck disable=SC2016 # the Compose line, unexpanded
	printf '    image: ${KNOWLEDGE_DUMP_IMAGE:-codeclarityce/knowledge-dump:2027-01-01@sha256:bbbb}\n' \
		>"$BENCHMARK_ROOT/.cloud/docker/docker-compose.yaml"
	run sh "$BENCHMARK" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pinned to $PIN"* ]]
	[ ! -s "$CURL_STUB_LOG" ]
}

@test "run refuses a pinned commit missing from the local repo" {
	app_input
	printf 'name\trepo\tcommit\tsubdir\napp\tapprepo\t%s\t.\n' 1111111111111111111111111111111111111111 \
		>"$BENCHMARK_DIR/inputs.tsv"
	fake_api
	run sh "$BENCHMARK" run --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"fetch"* ]]
}

@test "run stops when the analysis fails" {
	app_input
	fake_api
	sed -i 's/"status": "completed"/"status": "failure"/' "$CURL_STUB_RULES"
	run sh "$BENCHMARK" run --input app --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"app: analysis ana1 ended failure"* ]]
}

# One list row with a severity: id, package@version, score, class.
severity_row() {
	local pv=$2
	printf '{"Vulnerability": "%s", "Affected": [{"AffectedDependency": "%s", "AffectedVersion": "%s"}], "Severity": {"Severity": %s, "SeverityClass": "%s"}}' \
		"$1" "${pv%@*}" "${pv##*@}" "$3" "$4"
}

@test "run counts instances shown as None whose record has a CVSS vector or a GHSA severity" {
	app_input
	fake_api
	ground_truth app </dev/null
	page 0 1 "$(severity_row CVE-1 a@1.0.0 0 NONE)" "$(severity_row CVE-2 b@1.0.0 0 NONE)" \
		"$(severity_row CVE-3 c@1.0.0 9.3 CRITICAL)" "$(severity_row CVE-4 d@1.0.0 0 HIGH)" \
		>"$BATS_TEST_TMPDIR/pages/0.json"
	mkdir -p "$BATS_TEST_TMPDIR/details"
	echo '{"data": {"severities": {"cvss_4": {"base_score": 9.3}}}}' >"$BATS_TEST_TMPDIR/details/CVE-1.json"
	echo '{"data": {"severities": {}}}' >"$BATS_TEST_TMPDIR/details/CVE-2.json"
	run sh "$BENCHMARK" run --input app --out "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"Severity None with a CVSS vector or GHSA severity: 1"* ]]
	[[ "$output" == *"app  CVE-1  a@1.0.0"* ]]
	# Only the instances shown as None are looked up.
	[ "$(grep -c '/vulnerability/' "$CURL_STUB_LOG")" = 2 ]
	grep -q '/vulnerability/CVE-1?workspace=.&dependency=a&version=1.0.0$' "$CURL_STUB_LOG"
}

@test "the report says the None check was not recorded for older runs" {
	ground_truth app </dev/null
	page 0 1 | record app apprepo 0123456789abcdef0123 analysis-1
	run sh "$BENCHMARK" report "$REC"
	[ "$status" -eq 0 ]
	[[ "$output" == *"Severity None with a CVSS vector or GHSA severity: not recorded"* ]]
}

# A fixture folder with an npm manifest and lockfile stored renamed, listed as input "fx" next to "app".
fixture_input() {
	app_input
	mkdir -p "$BENCHMARK_DIR/fixtures/fx"
	echo '{"name": "fx"}' >"$BENCHMARK_DIR/fixtures/fx/package.json.fixture"
	echo '{"lockfileVersion": 3}' >"$BENCHMARK_DIR/fixtures/fx/package-lock.json.fixture"
	printf 'fx\tfixture\t-\t.\n' >>"$BENCHMARK_DIR/inputs.tsv"
}

@test "run analyses a fixture folder, archived at its root with real file names, next to pinned inputs" {
	fixture_input
	fake_api
	ground_truth fx <<'EOF'
CVE-1	a	1.0.0	TP	-	https://nvd.nist.gov/vuln/detail/CVE-1
EOF
	page 0 1 "$(row CVE-1 a@1.0.0)" >"$BATS_TEST_TMPDIR/pages/0.json"
	run sh "$BENCHMARK" run --input fx --out "$REC"
	[ "$status" -eq 0 ]
	[[ "$(squeezed)" == *"fx 1 1 0 0 1 1 0 100.0% 100.0%"* ]]
	[[ "$output" == *"fx: fixture fixtures/fx, analysis ana1"* ]]
	[ "$(tar -tzf "$REC/fx.tar.gz" | sort | tr '\n' ' ')" = "package-lock.json package.json " ]
	# The recorded run reports the same again offline.
	run sh "$BENCHMARK" report "$REC"
	[[ "$output" == *"fx: fixture fixtures/fx, analysis ana1"* ]]
}

@test "run uploads each committed benchmark fixture with its real manifest and lockfile names" {
	local src="$BATS_TEST_DIRNAME/../benchmark" name repo _rest inputs=()
	fake_api
	page 0 1 >"$BATS_TEST_TMPDIR/pages/0.json"
	printf 'name\trepo\tcommit\tsubdir\tworkspaces\n' >"$BENCHMARK_DIR/inputs.tsv"
	mkdir -p "$BENCHMARK_DIR/fixtures"
	while IFS="$(printf '\t')" read -r name repo _rest; do
		[ "$repo" = fixture ] || continue
		cp -R "$src/fixtures/$name" "$BENCHMARK_DIR/fixtures/"
		printf '%s\tfixture\t-\t.\t.\n' "$name" >>"$BENCHMARK_DIR/inputs.tsv"
		ground_truth "$name" </dev/null
		inputs+=(--input "$name")
	done <"$src/inputs.tsv"
	[ "${#inputs[@]}" -gt 0 ]
	run sh "$BENCHMARK" run "${inputs[@]}" --out "$REC"
	[ "$status" -eq 0 ]
	while IFS="$(printf '\t')" read -r name repo _rest; do
		[ "$repo" = fixture ] || continue
		case "$name" in
		npm-*) expected="package-lock.json package.json " ;;
		composer-*) expected="composer.json composer.lock " ;;
		*) echo "no expected listing for $name"; return 1 ;;
		esac
		[ "$(tar -tzf "$REC/$name.tar.gz" | sort | tr '\n' ' ')" = "$expected" ] || {
			echo "$name: $(tar -tzf "$REC/$name.tar.gz" | tr '\n' ' ')"
			return 1
		}
	done <"$src/inputs.tsv"
}

@test "run refuses a fixture input without its folder" {
	fixture_input
	rm -r "$BENCHMARK_DIR/fixtures/fx"
	fake_api
	run sh "$BENCHMARK" run --input fx --out "$REC"
	[ "$status" -eq 1 ]
	[[ "$output" == *"fx: no fixture folder at"* ]]
}

@test "every committed input has a ground truth, and every fixture input its folder" {
	dir="$BATS_TEST_DIRNAME/../benchmark"
	while IFS="$(printf '\t')" read -r name repo commit subdir _workspaces; do
		[ "$name" != name ] || continue
		[ -f "$dir/ground-truth/$name.tsv" ]
		if [ "$repo" = fixture ]; then
			[ "$commit" = - ]
			[ -d "$dir/fixtures/$name/$subdir" ]
		fi
	done <"$dir/inputs.tsv"
}
