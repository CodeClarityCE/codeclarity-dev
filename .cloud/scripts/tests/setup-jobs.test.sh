#!/bin/sh
# Tests that every one-shot setup job is listed where the stack is checked, and that the API
# waits for each one to complete, so a failed job keeps the app stopped.
# Usage: sh .cloud/scripts/tests/setup-jobs.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
deployment=${DEPLOYMENT_DIR:-$root/deployment}

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		[ -n "${3:-}" ] && echo "     $3"
	fi
}

# graph <compose files>: prints "job <service>" for each restart: "no" service and
# "dep <service> <dependency> <condition>" for each depends_on entry.
graph() {
	awk '
		/^[^ #]/ { in_services = ($0 ~ /^services:/); svc = ""; next }
		!in_services { next }
		/^  [A-Za-z0-9_.-]+:[ ]*$/ { svc = $1; sub(/:$/, "", svc); deps = 0; next }
		/^    [A-Za-z_]/ { deps = ($1 == "depends_on:") }
		/^    restart:[ ]*"no"/ { print "job", svc }
		deps && /^      [A-Za-z0-9_.-]+:[ ]*$/ { dep = $1; sub(/:$/, "", dep) }
		deps && /^        condition:/ { print "dep", svc, dep, $2 }
	' "$@"
}

# jobs_of <graph>: the jobs, sorted, one per line.
jobs_of() { awk '$1 == "job" { print $2 }' "$1" | sort -u; }

# waits <graph> <service>: every service <service> depends on, directly or through others.
waits() {
	awk -v start="$2" '
		$1 == "dep" { edges[$2] = edges[$2] " " $3 }
		END {
			queue[1] = start; n = 1; seen[start] = 1
			for (i = 1; i <= n; i++) {
				k = split(edges[queue[i]], next_deps, " ")
				for (j = 1; j <= k; j++) if (!seen[next_deps[j]]) { seen[next_deps[j]] = 1; queue[++n] = next_deps[j] }
			}
			for (s in seen) if (s != start) print s
		}
	' "$1" | sort -u
}

# listed <script>: the JOBS (or PRODUCTION_JOBS) list assigned in a script, sorted, one per line.
listed() { sed -n 's/^[[:space:]]*\(PRODUCTION_\)\{0,1\}JOBS="\(.*\)"$/\2/p' "$1" | head -1 | tr ' ' '\n' | sort -u; }

# stack <name> <graph> <jobs list name> <jobs list file>...: checks one stack.
stack() {
	name=$1 g=$2
	shift 2
	jobs_of "$g" >"$work/jobs"
	check "$name: has setup jobs" "$([ -s "$work/jobs" ] && echo ok || echo bad)"
	for script in "$@"; do
		listed "$script" >"$work/listed"
		check "$name: ${script#"$root"/} lists every setup job" \
			"$(cmp -s "$work/jobs" "$work/listed" && echo ok || echo bad)" \
			"jobs: $(tr '\n' ' ' <"$work/jobs"); listed: $(tr '\n' ' ' <"$work/listed")"
	done
	waits "$g" api >"$work/waits"
	missing=$(comm -23 "$work/jobs" "$work/waits" | tr '\n' ' ')
	check "$name: the API waits for every setup job" "$([ -z "$missing" ] && echo ok || echo bad)" "not waited for: $missing"
	loose=$(awk 'NR == FNR { job[$1] = 1; next } $1 == "dep" && job[$3] && $4 != "service_completed_successfully" { print $2 "->" $3 }' "$work/jobs" "$g" | tr '\n' ' ')
	check "$name: setup jobs are waited for until they complete successfully" "$([ -z "$loose" ] && echo ok || echo bad)" "$loose"
}

# The dev stack: every file in the Compose list.
files=$(grep -v '^[[:space:]]*\(#\|$\)' "$root/.cloud/docker/compose-files.txt" | sed "s|^|$root/|")
# shellcheck disable=SC2086 # one path per word
graph $files >"$work/dev"
stack dev "$work/dev" "$root/.cloud/scripts/tests/fresh-install/dev.sh"
check "dev: the instance backfill runs after the migrations" \
	"$(grep -qx 'dep vulnerability-instance-backfill migrate service_completed_successfully' "$work/dev" && echo ok || echo bad)"

# The production stack.
graph "$deployment/docker-compose.yaml" >"$work/prod"
stack production "$work/prod" "$root/.cloud/scripts/tests/fresh-install/lib.sh" "$root/.cloud/scripts/measure/reference-baseline.sh"
check "production: the instance backfill runs after the migrations" \
	"$(grep -qx 'dep vulnerability-instance-backfill migrate service_completed_successfully' "$work/prod" && echo ok || echo bad)"

# The parser itself, on a fixture with a job the API does not wait for.
cat >"$work/fixture.yaml" <<'EOF'
services:
  setup:
    image: x
    restart: "no"
  stray:
    image: x
    restart: "no"
  api:
    image: x
    depends_on:
      setup:
        condition: service_completed_successfully
volumes:
  data:
EOF
graph "$work/fixture.yaml" >"$work/fixture"
check "parser: finds both jobs" "$([ "$(jobs_of "$work/fixture" | tr '\n' ' ')" = "setup stray " ] && echo ok || echo bad)"
check "parser: sees that the API does not wait for stray" "$([ "$(waits "$work/fixture" api | tr '\n' ' ')" = "setup " ] && echo ok || echo bad)"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
