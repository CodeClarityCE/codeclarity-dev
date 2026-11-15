#!/bin/sh
# Tests make reset, on the host and through the broker, with stand-ins for docker and the broker.
# Usage: sh .cloud/scripts/tests/reset.test.sh
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_DOCKER_LOG="$work/docker-calls"
STUB_BROKER_LOG="$work/broker-calls"
export STUB_DOCKER_LOG STUB_BROKER_LOG

# A copy of the repo parts make reset uses, with the dev certificate already there.
repo="$work/repo"
mkdir -p "$repo/.cloud/docker/certs/rabbitmq"
cp "$root/Makefile" "$repo/"
cp -R "$root/.cloud/scripts" "$repo/.cloud/"
cp -R "$root/.cloud/docker/scripts" "$root/.cloud/docker/compose-files.txt" "$repo/.cloud/docker/"
touch "$repo/.cloud/docker/certs/rabbitmq/server.crt" "$repo/.cloud/docker/certs/rabbitmq/server.key"

# A socket file, so make takes the broker path.
socket="$work/broker.sock"
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$socket"

# reset runs make reset with its arguments; "host" or "broker" first picks the path.
reset() {
	path=$1
	shift
	: >"$STUB_DOCKER_LOG"
	: >"$STUB_BROKER_LOG"
	if [ "$path" = broker ]; then
		set -- BROKER_SOCKET="$socket" BROKER="sh $here/stubs/broker" "$@"
	else
		set -- BROKER_SOCKET="$work/no-socket" "$@"
	fi
	(unset CONFIRM && make --no-print-directory -C "$repo" reset "$@") >"$work/out" 2>&1
}

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out" "$STUB_DOCKER_LOG" "$STUB_BROKER_LOG"
	fi
}

test_reset_without_the_flag_refuses_and_runs_nothing() {
	for path in host broker; do
		for flag in "" CONFIRM=yes CONFIRM=; do
			result=ok
			reset "$path" ${flag:+"$flag"} && result=bad
			[ -s "$STUB_DOCKER_LOG" ] && result=bad
			[ -s "$STUB_BROKER_LOG" ] && result=bad
			grep -q 'CONFIRM=reset' "$work/out" || result=bad
			check "$path: make reset ${flag:-without a flag} exits non-zero and runs nothing" $result
		done
	done
}

test_an_exported_confirm_is_not_enough() {
	result=ok
	: >"$STUB_DOCKER_LOG"
	(CONFIRM=reset && export CONFIRM && make --no-print-directory -C "$repo" reset BROKER_SOCKET="$work/no-socket") >"$work/out" 2>&1 && result=bad
	[ -s "$STUB_DOCKER_LOG" ] && result=bad
	check "a CONFIRM left in the environment does not confirm" $result
}

test_host_reset_wipes_the_volumes_then_starts_the_stack() {
	result=ok
	reset host CONFIRM=reset || result=bad
	down=$(grep -n -e '-f ../../.cloud/docker/docker-compose.yaml .* down -v$' "$STUB_DOCKER_LOG" | cut -d: -f1)
	up=$(grep -n -e '-f ../../.cloud/docker/docker-compose.yaml .* up -d$' "$STUB_DOCKER_LOG" | cut -d: -f1)
	if [ -z "$down" ] || [ -z "$up" ] || [ "$down" -gt "$up" ]; then result=bad; fi
	check "host: make reset CONFIRM=reset removes the volumes, then runs make up" $result
}

test_broker_reset_passes_the_confirmation() {
	result=ok
	reset broker CONFIRM=reset || result=bad
	[ "$(cat "$STUB_BROKER_LOG")" = "reset CONFIRM=reset" ] || result=bad
	[ -s "$STUB_DOCKER_LOG" ] && result=bad
	check "broker: make reset CONFIRM=reset sends reset with its confirmation" $result
}

test_reset_without_the_flag_refuses_and_runs_nothing
test_an_exported_confirm_is_not_enough
test_host_reset_wipes_the_volumes_then_starts_the_stack
test_broker_reset_passes_the_confirmation

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
