#!/usr/bin/env bats
# Tests scripts/api-fuzz/api-fuzz.sh: the Schemathesis run against a stand-in API (curl and docker
# are stubs), the issue body built from its output, and the ci-failure issue (gh is the stub in stubs/).
# Run from the repo root: bats scripts/tests

FUZZ="$BATS_TEST_DIRNAME/../api-fuzz/api-fuzz.sh"
LOG_FIXTURE="$BATS_TEST_DIRNAME/fixtures/api-fuzz/schemathesis.log"

bats_require_minimum_version 1.5.0

setup() {
	PATH="$BATS_TEST_DIRNAME/stubs:$BATS_TEST_TMPDIR/bin:$PATH"
	mkdir -p "$BATS_TEST_TMPDIR/bin"
	export CURL_STUB_LOG="$BATS_TEST_TMPDIR/curl.log"
	export CURL_STUB_RULES="$BATS_TEST_TMPDIR/curl-rules.bash"
	export GH_STUB_LOG="$BATS_TEST_TMPDIR/gh.log"
	export GH_STUB_RULES="$BATS_TEST_TMPDIR/gh-rules.bash"
	export DOCKER_LOG="$BATS_TEST_TMPDIR/docker.args"
	export API_URL=https://localhost/api
	OUT="$BATS_TEST_TMPDIR/out"
	: >"$CURL_STUB_LOG"
	: >"$GH_STUB_LOG"
	# The dev account logs in with this token.
	cat >"$CURL_STUB_RULES" <<'EOF'
curl_stub() {
	[[ "$1 $2" == "POST https://localhost/api/auth/authenticate" ]] || return 1
	[[ "$3" == *'"email":"john.doe@codeclarity.io"'* ]] || return 1
	printf 'HTTP/1.1 201 Created\r\nset-cookie: __Host-Http-cc_access=dev-token-123; Path=/; HttpOnly; Secure; SameSite=Strict\r\n\r\n'
}
EOF
	stub_docker 0
}

# A docker stand-in: logs one argument per line, prints the fixture log and exits with $1.
stub_docker() {
	cat >"$BATS_TEST_TMPDIR/bin/docker" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$@" >"\$DOCKER_LOG"
cat "$LOG_FIXTURE"
exit $1
EOF
	chmod +x "$BATS_TEST_TMPDIR/bin/docker"
}

# The value following argument $1 in the logged docker call.
docker_arg() {
	grep -A1 -xF -- "$1" "$DOCKER_LOG" | sed -n 2p
}

# Every value following argument $1 in the logged docker call, one per line.
docker_args() {
	awk -v name="$1" 'take { print; take = 0; next } $0 == name { take = 1 }' "$DOCKER_LOG"
}

@test "run as the dev account logs in and fuzzes the API's OpenAPI description with the pinned image" {
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 0 ]
	grep -qxF "$(cat "$BATS_TEST_DIRNAME/../api-fuzz/schemathesis-image.txt")" "$DOCKER_LOG"
	grep -qxF "https://localhost/api/api_doc-json" "$DOCKER_LOG"
	[ "$(docker_arg --url)" = "https://localhost/api" ]
	# The web sign-in rides on its access cookie, with the header the API requires on it.
	[ "$(docker_args --header)" = $'Cookie: __Host-Http-cc_access=dev-token-123\nX-CodeClarity-CSRF: 1' ]
	[ "$(docker_arg --checks)" = "not_a_server_error,response_schema_conformance" ]
	[ "$(cat "$OUT/auth")" = dev-account ]
	[ "$(cat "$OUT/exit-code")" = 0 ]
	cmp -s "$LOG_FIXTURE" "$OUT/schemathesis.log"
}

@test "run as the dev account stops before its 15-minute access token expires" {
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 0 ]
	[ "$(docker_arg --max-time)" = 780 ]
}

@test "run as the dev account keeps a shorter MAX_TIME" {
	MAX_TIME=300 run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$(docker_arg --max-time)" = 300 ]
}

@test "run with an Organization token keeps the full MAX_TIME" {
	API_TOKEN=org-token run bash "$FUZZ" run --auth token --out "$OUT"
	[ "$(docker_arg --max-time)" = 1200 ]
}

@test "the Schemathesis image is pinned by version and digest" {
	run cat "$BATS_TEST_DIRNAME/../api-fuzz/schemathesis-image.txt"
	[[ "$output" =~ ^schemathesis/schemathesis:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]]
}

@test "run fails with Schemathesis' exit code and records it" {
	stub_docker 1
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 1 ]
	[ "$(cat "$OUT/exit-code")" = 1 ]
}

@test "run never prints the token" {
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[[ "$output" != *dev-token-123* ]]
}

@test "run skips the operations that would delete the account or change its password" {
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 0 ]
	grep -A1 -xF -- --exclude-operation-id "$DOCKER_LOG" | grep -qxF UsersController_deleteAccount
	grep -A1 -xF -- --exclude-operation-id "$DOCKER_LOG" | grep -qxF UsersController_updateAccountPassword
}

@test "run passes the seed and extra Schemathesis arguments through, for a replay" {
	run bash "$FUZZ" run --auth dev-account --out "$OUT" --seed 42 -- --include-method GET
	[ "$status" -eq 0 ]
	[ "$(docker_arg --seed)" = 42 ]
	[ "$(docker_arg --include-method)" = GET ]
}

@test "run mounts CURL_CA and tells Schemathesis to trust it" {
	echo cert >"$BATS_TEST_TMPDIR/ca.crt"
	CURL_CA="$BATS_TEST_TMPDIR/ca.crt" run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 0 ]
	[ "$(docker_arg --tls-verify)" = "$BATS_TEST_TMPDIR/ca.crt" ]
	grep -qxF "$BATS_TEST_TMPDIR/ca.crt:$BATS_TEST_TMPDIR/ca.crt:ro" "$DOCKER_LOG"
}

@test "run with the token provider sends API_TOKEN and does not log in" {
	API_TOKEN=org-token-9 run bash "$FUZZ" run --auth token --out "$OUT"
	[ "$status" -eq 0 ]
	[ "$(docker_args --header)" = "Authorization: Bearer org-token-9" ]
	[ ! -s "$CURL_STUB_LOG" ]
	[ "$(cat "$OUT/auth")" = token ]
}

@test "run with the token provider refuses an empty API_TOKEN" {
	API_TOKEN='' run bash "$FUZZ" run --auth token --out "$OUT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"API_TOKEN"* ]]
	[ ! -f "$DOCKER_LOG" ]
}

@test "run refuses an unknown auth provider and lists the known ones" {
	run bash "$FUZZ" run --auth nobody --out "$OUT"
	[ "$status" -eq 2 ]
	[[ "$output" == *"dev-account"* ]]
	[[ "$output" == *"token"* ]]
}

@test "run accepts the first known provider when awk writes one line at a time" {
	# Busybox awk in the bats image flushes per line; this one also waits, so a reader that stops early breaks it.
	local real_awk
	real_awk=$(command -v awk)
	cat >"$BATS_TEST_TMPDIR/bin/awk" <<EOF
#!/usr/bin/env bash
"$real_awk" "\$@" | while IFS= read -r l; do printf '%s\n' "\$l" 2>/dev/null || exit 141; sleep 0.1; done
EOF
	chmod +x "$BATS_TEST_TMPDIR/bin/awk"
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 0 ]
}

@test "run fails without calling Schemathesis when the dev account cannot log in" {
	echo 'curl_stub() { return 22; }' >"$CURL_STUB_RULES"
	run bash "$FUZZ" run --auth dev-account --out "$OUT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not log in"* ]]
	[ ! -f "$DOCKER_LOG" ]
}

# The dev account logs in, has personal org org-1, and the token endpoint answers with secret $1.
stub_token_api() {
	cat >"$CURL_STUB_RULES" <<RULES
curl_stub() {
	case "\$1 \$2" in
	"POST https://localhost/api/auth/authenticate") printf 'HTTP/1.1 201 Created\r\nset-cookie: __Host-Http-cc_access=dev-token-123; Path=/; HttpOnly; Secure; SameSite=Strict\r\n\r\n' ;;
	"GET https://localhost/api/org?page=0&entries_per_page=50")
		echo '{"data": [{"organization": {"id": "team-1", "personal": false}}, {"organization": {"id": "org-1", "personal": true}}]}' ;;
	"POST https://localhost/api/org/org-1/tokens")
		echo "\$3" >"$BATS_TEST_TMPDIR/token-body"
		echo '{"data": {"id": "t-1", "secret": "$1"}}' ;;
	*) return 22 ;;
	esac
}
RULES
}

@test "issue-token issues an analyze Organization token in the dev account's personal organization and prints its secret" {
	stub_token_api ccot_secret-1
	export CURL_STUB_HEADERS="$BATS_TEST_TMPDIR/headers"
	run --separate-stderr bash "$FUZZ" issue-token
	[ "$status" -eq 0 ]
	[ "$output" = ccot_secret-1 ]
	grep -qxF 'POST https://localhost/api/org/org-1/tokens' "$CURL_STUB_LOG"
	grep -qxF 'Cookie: __Host-Http-cc_access=dev-token-123' "$CURL_STUB_HEADERS"
	grep -qxF 'X-CodeClarity-CSRF: 1' "$CURL_STUB_HEADERS"
	[ "$(grep -c '^Authorization' "$CURL_STUB_HEADERS")" = 0 ]
	[ "$(jq -r .scope "$BATS_TEST_TMPDIR/token-body")" = analyze ]
	[ "$(jq -r .name "$BATS_TEST_TMPDIR/token-body")" = api-fuzz ]
	# It expires about a day from now.
	expires=$(date -d "$(jq -r .expires_on "$BATS_TEST_TMPDIR/token-body")" +%s)
	now=$(date +%s)
	((expires > now + 82800 && expires < now + 90000))
}

@test "issue-token fails when the API answers without a secret" {
	stub_token_api ''
	run bash "$FUZZ" issue-token
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not issue an Organization token"* ]]
}

@test "issue-token fails when the dev account cannot log in" {
	echo 'curl_stub() { return 22; }' >"$CURL_STUB_RULES"
	run bash "$FUZZ" issue-token
	[ "$status" -eq 1 ]
	[[ "$output" == *"could not log in"* ]]
}

# A recorded run in $OUT: provider $1, exit code $2, the fixture log.
recorded() {
	mkdir -p "$OUT"
	echo "$1" >"$OUT/auth"
	echo "$2" >"$OUT/exit-code"
	cp "$LOG_FIXTURE" "$OUT/schemathesis.log"
}

@test "issue-body names each failing operation with the request to replay, the seed and the run" {
	recorded dev-account 1
	RUN_URL=https://github.com/o/r/actions/runs/7 run bash "$FUZZ" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"<!-- api-fuzz: dev-account -->"* ]]
	[[ "$output" == *"GET /analyzer-templates/{language}"* ]]
	[[ "$output" == *"curl -X GET -H 'Authorization: [Filtered]' http://localhost:3000/analyzer-templates/0"* ]]
	[[ "$output" == *"GET /org"* ]]
	[[ "$output" == *"GET /knowledge/comparison"* ]]
	[[ "$output" == *"Read timed out"* ]]
	[[ "$output" == *"141460142896343815928945743138313291723"* ]]
	[[ "$output" == *"api-fuzz.sh run --auth dev-account --out DIR --seed 141460142896343815928945743138313291723"* ]]
	[[ "$output" == *"https://github.com/o/r/actions/runs/7"* ]]
	[[ "$output" == *"api-fuzz-regressions.integration.e2e-spec.ts"* ]]
	# The warnings and summary sections are noise in an issue.
	[[ "$output" != *"WARNINGS"* ]]
	[[ "$output" != *"Join our Discord"* ]]
	# Replay ids point into the runner's own example database.
	[[ "$output" != *"st replay"* ]]
}

@test "issue-body says when Schemathesis never ran" {
	mkdir -p "$OUT"
	run bash "$FUZZ" issue-body "$OUT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"Schemathesis did not run"* ]]
}

@test "issue-body keeps the issue under GitHub's size limit" {
	recorded dev-account 1
	for _ in $(seq 400); do sed -n '/^=* FAILURES =*$/,/^=* WARNINGS =*$/p' "$LOG_FIXTURE" | sed '1d;$d'; done >"$OUT/big"
	{ sed -n '1,/^=* FAILURES =*$/p' "$LOG_FIXTURE"; cat "$OUT/big"; sed -n '/^=* WARNINGS =*$/,$p' "$LOG_FIXTURE"; } >"$OUT/schemathesis.log"
	run bash "$FUZZ" issue-body "$OUT"
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

@test "report on a failed run opens a ci-failure issue titled after the provider" {
	recorded dev-account 1
	stub_gh
	GH_LABELS='ci-failure needs-triage' run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue create --title API fuzz failing as dev-account --label ci-failure --label needs-triage --body ' "$GH_STUB_LOG"
	run ! grep -q 'label create' "$GH_STUB_LOG"
}

@test "report creates the labels a repo lacks" {
	recorded dev-account 1
	stub_gh
	run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'label create ci-failure' "$GH_STUB_LOG"
	grep -q 'label create needs-triage' "$GH_STUB_LOG"
}

@test "report on a failed run comments on the provider's open issue instead of opening another" {
	recorded dev-account 1
	stub_gh
	GH_LABELS='ci-failure needs-triage' \
		GH_ISSUES='[{"number": 5, "title": "CI failing on main", "body": "x"}, {"number": 9, "title": "API fuzz failing as dev-account", "body": "<!-- api-fuzz: dev-account -->"}]' \
		run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue comment 9 --body ' "$GH_STUB_LOG"
	run ! grep -q 'issue create' "$GH_STUB_LOG"
}

@test "report on a run that never started Schemathesis still opens the issue" {
	mkdir -p "$OUT"
	echo dev-account >"$OUT/auth"
	stub_gh
	GH_LABELS='ci-failure needs-triage' run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue create --title API fuzz failing as dev-account' "$GH_STUB_LOG"
}

@test "report on a green run closes the provider's open issue" {
	recorded token 0
	stub_gh
	GH_ISSUES='[{"number": 3, "title": "API fuzz failing as dev-account", "body": "<!-- api-fuzz: dev-account -->"}, {"number": 4, "title": "API fuzz failing as token", "body": "<!-- api-fuzz: token -->"}]' \
		run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	grep -q 'issue comment 4 --body ' "$GH_STUB_LOG"
	grep -q 'issue close 4' "$GH_STUB_LOG"
	run ! grep -q 'issue close 3' "$GH_STUB_LOG"
}

@test "report on a green run with no open issue changes nothing" {
	recorded dev-account 0
	stub_gh
	run bash "$FUZZ" report "$OUT"
	[ "$status" -eq 0 ]
	run ! grep -q 'issue create\|issue comment\|issue close' "$GH_STUB_LOG"
}
