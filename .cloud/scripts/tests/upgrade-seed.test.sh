#!/bin/sh
# Tests the upgrade test's seeding and its check that the seeded data survived, against a stand-in API.
# Usage: sh .cloud/scripts/tests/upgrade-seed.test.sh
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

compose() { :; }
# shellcheck source=fresh-install/lib.sh
. "$root/.cloud/scripts/tests/fresh-install/lib.sh"
# shellcheck source=fresh-install/seed.sh
. "$root/.cloud/scripts/tests/fresh-install/seed.sh"
tests_passed=0 tests_failed=0

expect() {
	if [ "$2" = ok ]; then
		tests_passed=$((tests_passed + 1))
		echo "ok   $1"
	else
		tests_failed=$((tests_failed + 1))
		echo "FAIL $1"
		sed 's/^/     | /' "$work/out" 2>/dev/null
	fi
}

# A curl that answers from $STUB_API: route files named after "<method> <path?query>",
# logging each call and its body to $STUB_API/log. A missing route exits 22 as curl -f does.
mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/bin/sh
method=GET url="" body="" out=""
while [ $# -gt 0 ]; do
	case "$1" in
	-X) method=$2; shift ;;
	-d) body=$2; [ "$method" = GET ] && method=POST; shift ;;
	-o) out=$2; shift ;;
	-H | -F | -w | --form-string | --cacert) shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
path=${url#"$STUB_BASE"}
echo "$method $path $body" >>"$STUB_API/log"
file="$STUB_API/routes/$(printf '%s %s' "$method" "$path" | tr '/ ?&=' '_____')"
[ -f "$file" ] || exit 22
if [ -n "$out" ]; then cat "$file" >"$out"; else cat "$file"; fi
EOF
chmod +x "$work/bin/curl"
PATH="$work/bin:$PATH"
API_BASE=http://api.test
STUB_BASE=$API_BASE
STUB_API="$work/api"
export STUB_API STUB_BASE
CURL_CA=
token=stub-token
ANALYSIS_POLL_SECONDS=0

route() {
	mkdir -p "$STUB_API/routes"
	printf '%s\n' "$3" >"$STUB_API/routes/$(printf '%s %s' "$1" "$2" | tr '/ ?&=' '_____')"
}
unroute() {
	rm -f "$STUB_API/routes/$(printf '%s %s' "$1" "$2" | tr '/ ?&=' '_____')"
}

# An instance in which org o1 gets project p1, analysis a1 and ticket t1.
fresh_api() {
	rm -rf "$STUB_API" "$work/w"
	mkdir -p "$STUB_API/routes" "$work/w"
	WORK="$work/w"
	passed=0 failed=0
	route POST /org/o1/projects '{"id":"p1"}'
	route PATCH /org/o1/file/p1/upload '{}'
	route GET '/org/o1/analyzers?page=0&entries_per_page=100' '{"data":[{"id":"z1","name":"Default Analyzer"}]}'
	route POST /org/o1/projects/p1/analyses '{"id":"a1"}'
	route GET /org/o1/projects/p1/analyses/a1 '{"data":{"id":"a1","status":"completed","created_on":"2026-11-01T00:00:00Z","steps":[[{"Name":"js-sbom","Status":"success"}],[{"Name":"vuln-finder","Status":"success"},{"Name":"license-finder","Status":"success"}]]}}'
	route POST /org/o1/tickets '{"id":"t1"}'
	route GET /org/o1/projects/p1 '{"data":{"id":"p1","name":"upgrade-seed-app","description":"Seeded before the upgrade","added_on":"2026-11-01T00:00:00Z"}}'
	route GET '/org/o1/projects/p1/analysis/a1/sbom?workspace=.&page=0&entries_per_page=100' '{"data":[{"name":"ms","version":"2.1.3","prod":true}],"total_entries":1}'
	route GET '/org/o1/projects/p1/analysis/a1/licenses?workspace=.&page=0&entries_per_page=100' '{"data":[{"id":"MIT","name":"MIT License","deps_using_license":["ms@2.1.3"]}]}'
	route GET /org/o1/tickets/t1 '{"data":{"id":"t1","title":"Upgrade seed ticket","description":"Seeded before the upgrade","status":"OPEN","priority":"MEDIUM","type":"UPGRADE","project_id":"p1","source_analysis_id":"a1","affected_package":"ms","affected_version":"2.1.3","created_on":"2026-11-01T00:00:00Z","updated_on":null}}'
}

# Seeding goes through the API: a project from an uploaded archive, an analysis on it, a ticket on both.
fresh_api
seed_upgrade_data before o1 >"$work/out" 2>&1
r=ok
[ "$failed" = 0 ] && [ "$passed" -ge 1 ] || r=bad
grep -q '^POST /org/o1/projects ' "$STUB_API/log" || r=bad
grep -q '^PATCH /org/o1/file/p1/upload' "$STUB_API/log" || r=bad
grep -q '^POST /org/o1/projects/p1/analyses ' "$STUB_API/log" || r=bad
grep '^POST /org/o1/tickets ' "$STUB_API/log" | sed 's/^POST \/org\/o1\/tickets //' |
	jq -e '.project_id == "p1" and .source_analysis_id == "a1"' >/dev/null 2>&1 || r=bad
expect "seeding creates a project, uploads it, runs an analysis and opens a ticket on both, all over HTTP" $r

# Reads the seeded data back after an upgrade; prints its check lines to $work/out.
after_upgrade() {
	passed=0 failed=0
	check_seeded_data after >"$work/out" 2>&1
}

after_upgrade
r=ok
[ "$failed" = 0 ] && [ "$passed" = 3 ] || r=bad
for kind in project analysis ticket; do grep -q "^ok   after: the seeded $kind" "$work/out" || r=bad; done
expect "unchanged seeded data passes the project, analysis and ticket checks" $r

# Seeds afresh, applies the breakage "$2 $3 $4" to the stand-in API, and expects only the $1 check to fail.
broken() {
	fresh_api
	seed_upgrade_data before o1 >/dev/null 2>&1
	if [ "$2" = unroute ]; then unroute "$3" "$4"; else route "$2" "$3" "$4"; fi
	after_upgrade
	r=ok
	[ "$failed" = 1 ] && [ "$passed" = 2 ] || r=bad
	grep -q "^FAIL after: the seeded $1 is intact" "$work/out" || r=bad
}

broken ticket unroute GET /org/o1/tickets/t1
expect "a ticket the upgrade deleted fails the ticket check" $r
broken ticket GET /org/o1/tickets/t1 '{"data":{"id":"t1","title":"Upgrade seed ticket","description":"","status":"OPEN","priority":"MEDIUM","type":"UPGRADE","project_id":"p1","source_analysis_id":"a1","affected_package":"ms","affected_version":"2.1.3","created_on":"2026-11-01T00:00:00Z"}}'
expect "a ticket whose description the upgrade emptied fails the ticket check" $r
broken analysis GET '/org/o1/projects/p1/analysis/a1/sbom?workspace=.&page=0&entries_per_page=100' '{"data":[],"total_entries":0}'
expect "an analysis whose SBOM results the upgrade dropped fails the analysis check" $r
broken analysis unroute GET '/org/o1/projects/p1/analysis/a1/licenses?workspace=.&page=0&entries_per_page=100'
expect "an analysis whose licence results are gone fails the analysis check" $r
broken project GET /org/o1/projects/p1 '{"data":{"id":"p1","name":"upgrade-seed-app","description":null,"added_on":"2026-11-01T00:00:00Z"}}'
expect "a project whose description the upgrade dropped fails the project check" $r

# An analysis that shows no dependency before the upgrade would compare equal to one that lost them.
fresh_api
route GET '/org/o1/projects/p1/analysis/a1/sbom?workspace=.&page=0&entries_per_page=100' '{"data":[],"total_entries":0}'
seed_upgrade_data before o1 >"$work/out" 2>&1
r=ok
[ "$failed" = 1 ] || r=bad
grep -q '^FAIL before: the seeded analysis lists ms@2.1.3 in its SBOM and licences' "$work/out" || r=bad
expect "seeding fails when the seeded analysis shows no ms@2.1.3 to compare later" $r

# With nothing seeded, there is nothing to compare, so every check fails rather than passing on empty.
fresh_api
after_upgrade
r=ok
[ "$failed" = 3 ] && [ "$passed" = 0 ] || r=bad
expect "with no seeded data recorded, all three checks fail" $r

# The upgrade journey logs in as the seeded account from a file only its owner reads.
LOGIN_EMAIL=operator@example.com
LOGIN_PASSWORD="it's a \$secret"
rm -f "$work/journey.env"
write_journey_login "$work/journey.env" >"$work/out" 2>&1
r=ok
[ "$(stat -c %a "$work/journey.env" 2>/dev/null)" = 600 ] || r=bad
# shellcheck disable=SC2016 # the variables expand in the inner shell
got=$(env -i sh -c 'set -a; . "$1"; printf "%s|%s" "$E2E_LOGIN_EMAIL" "$E2E_LOGIN_PASSWORD"' sh "$work/journey.env" 2>&1) || r=bad
[ "$got" = "operator@example.com|it's a \$secret" ] || r=bad
expect "the journey login file gives the seeded account's email and password, readable by its owner only (got $got)" $r

echo "$tests_passed passed, $tests_failed failed"
[ "$tests_failed" -eq 0 ]
