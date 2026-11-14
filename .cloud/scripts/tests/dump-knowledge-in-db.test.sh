#!/bin/sh
# Tests dump-knowledge-in-db.sh with stand-in pg_dump and psql. Needs jq and sha256sum.
# Usage: sh .cloud/scripts/tests/dump-knowledge-in-db.test.sh
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../dump-knowledge-in-db.sh"
chmod +x "$here/stubs/pg_dump" "$here/stubs/psql"
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass_report='{
  "passed": true,
  "checks": [
    {
      "name": "nvd.rows",
      "expected": "> 0",
      "actual": 402754,
      "pass": true
    }
  ]
}'
fail_report='{
  "passed": false,
  "checks": [
    {
      "name": "nvd.rows",
      "expected": "> 0",
      "actual": 0,
      "pass": false
    }
  ]
}'

# sha256 of the stub's 100-byte dump ("123456789101112..."), computed once by hand.
known_sha_100=c5f02cf031cac250c7e132b6a62bf6e3d5cbac13771a194b00470bb489b7058f

# Each test gets an empty dump directory holding one old file.
fresh() {
	dir="$work/$1"
	mkdir -p "$dir"
	echo old >"$dir/knowledge.dump"
}

# dump runs the script on a dump directory with a gate report on stdin.
dump() {
	DUMP_DIR="$1" SPLIT_BYTES="${SPLIT_BYTES:-1000}" sh "$script" >"$work/out" 2>&1
}

listing() {
	# shellcheck disable=SC2012 # test dirs hold only plain file names
	(cd "$1" && ls -A | LC_ALL=C sort)
}

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out"
	fi
}

test_failed_gate_writes_nothing() {
	fresh failed_gate
	before=$(listing "$dir")
	result=ok
	printf '%s\n' "$fail_report" | dump "$dir" && result=bad
	[ "$(listing "$dir")" = "$before" ] || result=bad
	[ "$(cat "$dir/knowledge.dump")" = old ] || result=bad
	grep -q "gate did not pass" "$work/out" || result=bad
	check "a failed gate report writes nothing" $result
}

test_passing_gate_writes_dumps_and_manifest() {
	fresh passing_gate
	result=ok
	printf '%s\n' "$pass_report" | dump "$dir" || result=bad
	m="$dir/knowledge-manifest.json"
	[ "$(listing "$dir")" = "$(printf '%s\n' config.dump knowledge-manifest.json knowledge-manifest.sha256 knowledge.dump)" ] || result=bad
	[ "$(cat "$dir/knowledge.dump")" != old ] || result=bad
	jq -e '.format == 1' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.postgres_version == "18.6" and .pg_dump_version == "pg_dump (PostgreSQL) 18.6"' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.build_date | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.sources[0] == {"source":"nvd","watermark":"2026-11-10T08:00:00+00:00","last_outcome":"success","upstream_total":421910,"rows":402754,"stored_records":421910}' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.migrations == {"knowledge":["Baseline-knowledge","Second-knowledge"],"config":["Baseline-config","Second-config"]}' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.gate.passed == true and .gate.checks[0].name == "nvd.rows"' "$m" >/dev/null 2>&1 || result=bad
	jq -e '[.files[] | {name, database, size, parts}] == [{"name":"knowledge.dump","database":"knowledge","size":100,"parts":[]},{"name":"config.dump","database":"config","size":100,"parts":[]}]' "$m" >/dev/null 2>&1 || result=bad
	jq -e --arg sha "$known_sha_100" '[.files[].sha256] == [$sha, $sha]' "$m" >/dev/null 2>&1 || result=bad
	(cd "$dir" && sha256sum -c knowledge-manifest.sha256) >>"$work/out" 2>&1 || result=bad
	check "a passing gate writes both dumps, a manifest and a checksum list" $result
}

test_large_dump_is_split_into_checksummed_parts() {
	fresh split
	result=ok
	printf '%s\n' "$pass_report" | STUB_DUMP_BYTES_knowledge=2500 dump "$dir" || result=bad
	m="$dir/knowledge-manifest.json"
	[ "$(listing "$dir")" = "$(printf '%s\n' config.dump knowledge-manifest.json knowledge-manifest.sha256 knowledge.dump.part-aaa knowledge.dump.part-aab knowledge.dump.part-aac)" ] || result=bad
	jq -e '.files[0] | .name == "knowledge.dump" and .size == 2500 and .sha256 == "cddc81c0741412111944f1ebfce6d068846260cd4fc356e6edad93be29503968"' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.files[0].parts == [
		{"name":"knowledge.dump.part-aaa","size":1000,"sha256":"8d7c0a443d9f79d625844ac35a8a84243c5ce87ca5f21683effcb5aa239bc1bf"},
		{"name":"knowledge.dump.part-aab","size":1000,"sha256":"1ac4c0c2049ffe4e4761f02b18bcaca292fcded2d8dfcdea75089a6334a6a02d"},
		{"name":"knowledge.dump.part-aac","size":500,"sha256":"9dbd0eadc9ac2b45f63c946a6a779db5ac3fdc3bf3f22af054369b984c487337"}]' "$m" >/dev/null 2>&1 || result=bad
	jq -e '.files[1].parts == []' "$m" >/dev/null 2>&1 || result=bad
	[ "$(cut -d' ' -f3 "$dir/knowledge-manifest.sha256" | tr '\n' ' ')" = "knowledge.dump.part-aaa knowledge.dump.part-aab knowledge.dump.part-aac config.dump " ] || result=bad
	(cd "$dir" && sha256sum -c knowledge-manifest.sha256) >>"$work/out" 2>&1 || result=bad
	[ "$(cat "$dir"/knowledge.dump.part-* | sha256sum | cut -d' ' -f1)" = cddc81c0741412111944f1ebfce6d068846260cd4fc356e6edad93be29503968 ] || result=bad
	check "a dump over SPLIT_BYTES is replaced by checksummed parts" $result
}

test_a_new_dump_removes_old_parts() {
	fresh old_parts
	result=ok
	printf '%s\n' "$pass_report" | STUB_DUMP_BYTES_knowledge=2500 dump "$dir" || result=bad
	printf '%s\n' "$pass_report" | dump "$dir" || result=bad
	[ "$(listing "$dir")" = "$(printf '%s\n' config.dump knowledge-manifest.json knowledge-manifest.sha256 knowledge.dump)" ] || result=bad
	check "a new unsplit dump removes the parts of an earlier split one" $result
}

test_failed_pg_dump_keeps_the_previous_dump() {
	fresh pg_dump_fails
	printf '%s\n' "$pass_report" | dump "$dir"
	before=$(cd "$dir" && sha256sum ./* | LC_ALL=C sort)
	result=ok
	printf '%s\n' "$pass_report" | STUB_PG_DUMP_FAIL=config dump "$dir" && result=bad
	[ "$(cd "$dir" && sha256sum ./* | LC_ALL=C sort)" = "$before" ] || result=bad
	# shellcheck disable=SC2010 # test dirs hold only plain file names
	[ -z "$(cd "$dir" && ls -A | grep '^\.')" ] || result=bad
	check "a failed pg_dump leaves the previous dump untouched and no staging files" $result
}

test_package_and_version_ship_empty() {
	fresh ship_empty
	result=ok
	log="$work/pg_dump.log"
	: >"$log"
	printf '%s\n' "$pass_report" | STUB_PG_DUMP_LOG="$log" dump "$dir" || result=bad
	grep -e '-d knowledge' "$log" | grep -q -e '--exclude-table-data=package --exclude-table-data=version' || result=bad
	grep -e '-d config' "$log" | grep -q -e '--exclude-table-data' && result=bad
	cat "$log" >>"$work/out"
	check "knowledge ships the package and version tables without data" $result
}

test_failed_gate_writes_nothing
test_package_and_version_ship_empty
test_passing_gate_writes_dumps_and_manifest
test_large_dump_is_split_into_checksummed_parts
test_a_new_dump_removes_old_parts
test_failed_pg_dump_keeps_the_previous_dump

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
