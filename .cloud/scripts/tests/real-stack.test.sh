#!/bin/sh
# Tests the real-stack e2e override: the dev stack's Compose file list never names it, and merged
# over the deployment file it starts only the setup jobs, the services the journeys need and a mail
# catcher. Also tests the knowledge update the journeys rely on (stack.sh knowledge-update, with a
# stand-in docker) and its fixture advisories. The service checks need docker compose and are
# skipped without it.
# Usage: sh .cloud/scripts/tests/real-stack.test.sh
root=$(cd "$(dirname "$0")/../../.." && pwd)
override=.cloud/scripts/tests/real-stack/docker-compose.yaml
passed=0 failed=0 skipped=0

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
	fi
}

result=ok
[ -f "$root/$override" ] || result=bad
check "the override exists" $result

result=ok
grep -v '^#' "$root/.cloud/docker/compose-files.txt" | grep -q 'real-stack' && result=bad
check "the dev stack's Compose file list does not name the override" $result

# Golden journey 7 runs the CLI in the same job, against the stack the browser journey used.
result=ok
workflow="$root/.github/workflows/e2e-real-stack.yml"
grep -q 'sh .cloud/scripts/tests/real-stack/cli-journey.sh ' "$workflow" || result=bad
check "the real-stack workflow runs golden journey 7 (the CLI)" $result

if docker compose version >/dev/null 2>&1 && [ -f "$root/deployment/docker-compose.yaml" ]; then
	want="api db default-analyzer frontend generate-secrets knowledge-restore mail migrate pgbouncer plugin-js-sbom
plugin-license-finder plugin-php-sbom plugin-vuln-finder rabbitmq service-dispatcher service-downloader
service-follower version-check vulnerability-instance-backfill"
	result=ok
	got=$(docker compose --project-directory "$root/deployment" -f "$root/deployment/docker-compose.yaml" \
		-f "$root/$override" config --services | sort | tr '\n' ' ') || result=bad
	[ "$got" = "$(echo "$want" | tr '\n' ' ' | tr ' ' '\n' | sort | tr '\n' ' ')" ] || result=bad
	check "merged over the deployment file it starts only the journey's services (got: $got)" $result

	result=ok
	COMPOSE_PROFILES=knowledge-update docker compose --project-directory "$root/deployment" \
		-f "$root/deployment/docker-compose.yaml" -f "$root/$override" config --services |
		grep -qx service-knowledge || result=bad
	check "with the knowledge-update profile, service-knowledge is in the config, so its image gets built" $result
else
	skipped=$((skipped + 1))
	echo "skip the service check needs docker compose and the deployment submodule"
fi

# The fixture advisories: the dump's GHSA-w9mr-4mfr-499f (ms < 2.0.0) is kept and GHSA-3fx5-fwvr-xrjg
# (ms < 0.7.1) is added, so ms@0.7.0 goes from one advisory to two.
advisories="$root/.cloud/scripts/tests/real-stack/advisory-database/advisories/github-reviewed"
for pair in "2023/01/GHSA-w9mr-4mfr-499f 2.0.0" "2017/10/GHSA-3fx5-fwvr-xrjg 0.7.1"; do
	path=${pair% *} fixed=${pair#* } id=${path##*/}
	result=ok
	jq -e --arg id "$id" --arg fixed "$fixed" '.id == $id and any(.affected[];
		.package == {"ecosystem": "npm", "name": "ms", "purl": "pkg:npm/ms"} and
		any(.ranges[].events[]; .fixed == $fixed))' "$advisories/$path/$id.json" >/dev/null 2>&1 || result=bad
	check "the fixture advisory $id affects npm ms before $fixed" $result
done
result=ok
[ "$(find "$advisories" -name '*.json' | wc -l | tr -d ' ')" = 2 ] || result=bad
check "the fixture holds only those two advisories" $result

# stack.sh knowledge-update, with a docker that logs its arguments.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
printf '#!/bin/sh\necho "$*" >>"%s/docker.log"\n' "$work" >"$work/bin/docker"
chmod +x "$work/bin/docker"
result=ok
PATH="$work/bin:$PATH" DEPLOYMENT_DIR="$work" sh "$root/.cloud/scripts/tests/real-stack/stack.sh" knowledge-update \
	>"$work/out" 2>&1 || result=bad
grep -q " run --rm --no-deps -T -v $root/.cloud/scripts/tests/real-stack/advisory-database:/advisory-database:ro service-knowledge ./plugin -knowledge -action update-asof -asof $(date -u +%Y-%m-%d) -advisory-repo /advisory-database\$" \
	"$work/docker.log" 2>/dev/null || result=bad
check "knowledge-update runs one update-asof from the fixture in service-knowledge, starting nothing else" $result
[ "$result" = ok ] || cat "$work/out" "$work/docker.log" 2>/dev/null

# stack.sh psql, with STACK_OVERRIDE merged last.
: >"$work/docker.log"
result=ok
echo 'SELECT 1;' | STACK_OVERRIDE=/gate.yaml PATH="$work/bin:$PATH" DEPLOYMENT_DIR="$work" \
	sh "$root/.cloud/scripts/tests/real-stack/stack.sh" psql knowledge >"$work/out" 2>&1 || result=bad
grep -q "^compose --project-directory $work -f $work/docker-compose.yaml -f $root/.cloud/scripts/tests/real-stack/docker-compose.yaml -f /gate.yaml exec -T db sh -c " \
	"$work/docker.log" 2>/dev/null || result=bad
# The script's last line ends with psql's -d "$1", then the database as $1.
# shellcheck disable=SC2016 # a literal "$1" and end of line
grep -q '\-d "\$1" psql knowledge$' "$work/docker.log" 2>/dev/null || result=bad
check "psql runs psql in the db container on the database named, with STACK_OVERRIDE merged last" $result
[ "$result" = ok ] || cat "$work/out" "$work/docker.log" 2>/dev/null

# stack.sh offline, with a docker that answers for a container on networks $NETWORKS, internal ones in $INTERNAL.
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
case "$*" in
"compose "*" ps -q service-follower") echo c1 ;;
"inspect "*) printf '%s\n' $NETWORKS ;;
"network inspect "*)
	for n; do :; done
	case " $INTERNAL " in *" $n "*) echo true ;; *) echo false ;; esac
	;;
*) exit 1 ;;
esac
EOF
result=ok
NETWORKS=gate_offline INTERNAL=gate_offline PATH="$work/bin:$PATH" DEPLOYMENT_DIR="$work" \
	sh "$root/.cloud/scripts/tests/real-stack/stack.sh" offline service-follower >"$work/out" 2>&1 || result=bad
check "offline passes for a service only on internal networks" $result
[ "$result" = ok ] || cat "$work/out"
result=ok
NETWORKS="gate_offline gate_default" INTERNAL=gate_offline PATH="$work/bin:$PATH" DEPLOYMENT_DIR="$work" \
	sh "$root/.cloud/scripts/tests/real-stack/stack.sh" offline service-follower >"$work/out" 2>&1 && result=bad
grep -q "on network gate_default, which reaches outside" "$work/out" || result=bad
check "offline fails, naming it, for a service on a network with outbound access" $result
[ "$result" = ok ] || cat "$work/out"

# The results gate's Compose file leaves the follower only on an internal network, with pgbouncer and rabbitmq.
if docker compose version >/dev/null 2>&1 && [ -f "$root/deployment/docker-compose.yaml" ]; then
	result=ok
	config=$(docker compose --project-directory "$root/deployment" -f "$root/deployment/docker-compose.yaml" \
		-f "$root/$override" -f "$root/scripts/results-gate/docker-compose.yaml" config --format json) || result=bad
	echo "$config" | jq -e '(.services["service-follower"].networks | keys) == ["registry-offline"] and
		.networks["registry-offline"].internal == true and
		(.services.pgbouncer.networks | has("registry-offline")) and (.services.rabbitmq.networks | has("registry-offline"))' \
		>/dev/null || result=bad
	check "the results gate's Compose file puts the follower only on an internal network" $result
else
	skipped=$((skipped + 1))
	echo "skip the results gate's network check needs docker compose and the deployment submodule"
fi

echo "$passed passed, $failed failed, $skipped skipped"
[ "$failed" -eq 0 ]
