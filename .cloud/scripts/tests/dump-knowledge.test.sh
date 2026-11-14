#!/bin/sh
# Tests the host dump-knowledge.sh with a stand-in docker, pg_dump and psql.
# Usage: sh .cloud/scripts/tests/dump-knowledge.test.sh
here=$(cd "$(dirname "$0")" && pwd)
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_DOCKER_LOG="$work/docker-calls"
export STUB_DOCKER_LOG

# fake_api writes API migration files for one folder: <file name> <class name> pairs.
fake_api() {
	folder="$work/api/src/migrations/$1"
	shift
	mkdir -p "$folder"
	while [ $# -gt 0 ]; do
		printf 'import { MigrationInterface } from "typeorm";\n\nexport class %s implements MigrationInterface {}\n' "$2" >"$folder/$1"
		shift 2
	done
}

# dump runs dump-knowledge.sh against a dump directory, with the gate reporting $1.
dump() {
	mkdir -p "$work/dump"
	: >"$STUB_DOCKER_LOG"
	(cd "$here/.." && STUB_GATE_REPORT="$1" DUMP_DIR="$work/dump" API_DIR="$work/api" \
		sh dump-knowledge.sh) >"$work/out" 2>&1
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

test_the_gate_expects_the_api_migrations() {
	fake_api knowledge 1754600000000-CreateKnowledgeBaseline.ts CreateKnowledgeBaseline1754600000000 \
		1794528000000-AddUpstreamTotal.ts AddUpstreamTotal1794528000000
	fake_api config 1754600000000-CreateConfigBaseline.ts CreateConfigBaseline1754600000000
	result=ok
	dump '{"passed": true, "checks": []}' || result=bad
	gate=$(grep service-package-follower "$STUB_DOCKER_LOG")
	echo "$gate" | grep -q -e '-e KNOWLEDGE_EXPECTED_MIGRATIONS_KNOWLEDGE=CreateKnowledgeBaseline1754600000000,AddUpstreamTotal1794528000000 ' || result=bad
	echo "$gate" | grep -q -e '-e KNOWLEDGE_EXPECTED_MIGRATIONS_CONFIG=CreateConfigBaseline1754600000000 ' || result=bad
	[ -f "$work/dump/knowledge-manifest.json" ] || result=bad
	check "the gate expects the migrations in the API checkout" $result
}

test_a_failed_gate_dumps_nothing() {
	rm -rf "$work/dump"
	result=ok
	dump '{"passed": false, "checks": []}' && result=bad
	grep -q -e '-T db' "$STUB_DOCKER_LOG" && result=bad
	[ -z "$(ls -A "$work/dump")" ] || result=bad
	check "a failed gate dumps nothing" $result
}

test_the_gate_expects_the_api_migrations
test_a_failed_gate_dumps_nothing

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
