#!/bin/sh
# Tests the host knowledge-update.sh with a stand-in docker: the update runs in the stack's
# service-package-follower container, so the host needs no Go.
# Usage: sh .cloud/scripts/tests/knowledge-update.test.sh
here=$(cd "$(dirname "$0")" && pwd)
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_DOCKER_LOG="$work/docker-calls"
STUB_ENV_LOG="$work/env"
STUB_GATE_REPORT=$(printf '%s' '"passed": true')
SECRETS_FILE="$work/.env.secrets"
export STUB_DOCKER_LOG STUB_ENV_LOG STUB_GATE_REPORT SECRETS_FILE

# update runs knowledge-update.sh with its arguments, without an NVD_API_KEY of the caller's.
update() {
	: >"$STUB_DOCKER_LOG"
	: >"$STUB_ENV_LOG"
	(cd "$here/.." && env -u NVD_API_KEY sh knowledge-update.sh "$@") >"$work/out" 2>&1
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

test_the_osv_update_runs_in_the_stack() {
	rm -f "$SECRETS_FILE"
	result=ok
	update update-osv || result=bad
	grep -q -e ' exec -T -w /codeclarity/services/knowledge service-package-follower go run . -knowledge -action update-osv$' \
		"$STUB_DOCKER_LOG" || result=bad
	check "the OSV update runs in the stack's Go container and needs no key" $result
}

test_the_full_update_gets_the_key_from_the_secrets_file_outside_argv() {
	printf 'NVD_API_KEY="abc-123"\n' >"$SECRETS_FILE"
	result=ok
	update update || result=bad
	grep -q -e ' exec -T -w /codeclarity/services/knowledge -e NVD_API_KEY service-package-follower go run . -knowledge -action update$' \
		"$STUB_DOCKER_LOG" || result=bad
	grep -qx 'NVD_API_KEY=abc-123' "$STUB_ENV_LOG" || result=bad
	grep -q abc-123 "$STUB_DOCKER_LOG" && result=bad
	check "the full update passes the key from the secrets file in docker's environment, not argv" $result
}

test_the_full_update_refuses_without_a_key() {
	printf 'NVD_API_KEY=!ChangeMe!\n' >"$SECRETS_FILE"
	result=ok
	update update && result=bad
	[ -s "$STUB_DOCKER_LOG" ] && result=bad
	grep -q 'NVD_API_KEY' "$work/out" || result=bad
	check "the full update refuses to start without a key" $result
}

test_a_failed_update_fails_the_script() {
	rm -f "$SECRETS_FILE"
	result=ok
	STUB_GATE_REPORT=failed update update-osv && result=bad
	check "a failed update fails the script" $result
}

test_the_osv_update_runs_in_the_stack
test_the_full_update_gets_the_key_from_the_secrets_file_outside_argv
test_the_full_update_refuses_without_a_key
test_a_failed_update_fails_the_script

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
