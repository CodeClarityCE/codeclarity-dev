#!/bin/sh
# Tests that compose.sh and the scripts using it pass the dev Compose file list to docker.
# Usage: sh .cloud/scripts/tests/compose.test.sh
here=$(cd "$(dirname "$0")" && pwd)
scripts=$(cd "$here/.." && pwd)

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A docker stand-in that only logs its arguments.
mkdir -p "$work/bin"
printf '#!/bin/sh\necho "$*" >>"$STUB_DOCKER_LOG"\n' >"$work/bin/docker"
chmod +x "$work/bin/docker"
PATH="$work/bin:$PATH"
STUB_DOCKER_LOG="$work/docker-calls"
export PATH STUB_DOCKER_LOG

# A fake repo with a two-file list; only the second file has a debug overlay.
root="$work/repo"
mkdir -p "$root/.cloud/docker" "$root/svc"
printf '# comment\n.cloud/docker/docker-compose.yaml\n\nsvc/docker-compose.yaml\n' >"$root/.cloud/docker/compose-files.txt"
touch "$root/.cloud/docker/docker-compose.yaml" "$root/svc/docker-compose.yaml" "$root/svc/docker-compose.debug.yaml"
files="-f $root/.cloud/docker/docker-compose.yaml -f $root/svc/docker-compose.yaml"
debug_files="-f $root/.cloud/docker/docker-compose.yaml -f $root/svc/docker-compose.yaml -f $root/svc/docker-compose.debug.yaml"

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$STUB_DOCKER_LOG"
	fi
}

# calls runs a shell snippet from .cloud/scripts against the fake repo; $2 is the expected docker call.
calls() {
	: >"$STUB_DOCKER_LOG"
	(cd "$scripts" && COMPOSE_ROOT="$root" sh -c "$2") >/dev/null 2>&1
	if [ "$(cat "$STUB_DOCKER_LOG")" = "$3" ]; then check "$1" ok; else check "$1" bad; fi
}

calls "compose passes the listed files in order, then its arguments" \
	'. ./compose.sh && compose exec -T db "a b"' "compose $files exec -T db a b"
calls "compose_debug adds each file's debug overlay after it" \
	'. ./compose.sh && compose_debug up -d' "compose $debug_files up -d"
calls "down.sh stops one service" 'sh down.sh api' "compose $files down api"
calls "build.sh builds everything" 'sh build.sh' "compose $files build"
calls "logs.sh follows the logs" 'sh logs.sh' "compose $files logs -f"
calls "dump-db.sh dumps one database" 'sh dump-db.sh codeclarity' \
	"compose $files exec db sh -c PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d codeclarity -Fc > /dump/codeclarity.dump"
calls "dump-db-dated.sh dumps knowledge then config" 'sh dump-db-dated.sh compose-test-label' \
	"compose $files exec db sh -c PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d knowledge -Fc > /dump/knowledge-compose-test-label.dump
compose $files exec db sh -c PGPASSWORD=\$POSTGRES_PASSWORD pg_dump -w -U postgres -d config -Fc > /dump/config-compose-test-label.dump"
calls "build-debug.sh builds with the overlays" 'sh build-debug.sh' "compose $debug_files build"

: >"$STUB_DOCKER_LOG"
result=ok
(cd "$scripts" && COMPOSE_ROOT="$work/empty" sh -c '. ./compose.sh && compose up -d') >/dev/null 2>&1 && result=bad
[ -s "$STUB_DOCKER_LOG" ] && result=bad
check "compose runs nothing without the list" $result

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
