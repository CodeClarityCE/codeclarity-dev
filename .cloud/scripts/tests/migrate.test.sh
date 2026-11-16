#!/bin/sh
# Tests the host migrate.sh with a stand-in docker.
# Usage: sh .cloud/scripts/tests/migrate.test.sh
here=$(cd "$(dirname "$0")" && pwd)
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_DOCKER_LOG="$work/docker-calls"
export STUB_DOCKER_LOG

# migrate runs migrate.sh with its arguments, the job exiting with STUB_MIGRATE_EXIT.
migrate() {
	: >"$STUB_DOCKER_LOG"
	(cd "$here/.." && sh migrate.sh "$@") >"$work/out" 2>&1
}

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out" "$STUB_DOCKER_LOG"
	fi
}

test_every_database_runs_in_the_migrate_job() {
	result=ok
	migrate || result=bad
	grep -q -e '-f ../../api/.cloud/docker/docker-compose.yaml .* run --rm migrate$' "$STUB_DOCKER_LOG" || result=bad
	check "every database migrates in the migrate job" $result
}

test_one_database_is_passed_to_the_job() {
	result=ok
	migrate config || result=bad
	grep -q -e ' run --rm migrate config$' "$STUB_DOCKER_LOG" || result=bad
	check "one database is passed to the job" $result
}

test_a_failed_job_fails_the_script() {
	result=ok
	STUB_MIGRATE_EXIT=3 migrate && result=bad
	check "a failed job fails the script" $result
}

test_every_database_runs_in_the_migrate_job
test_one_database_is_passed_to_the_job
test_a_failed_job_fails_the_script

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
