#!/bin/sh
# Tests the memory budget check against the deployment Compose file and broken fixtures.
# Usage: sh .cloud/scripts/tests/memory-budget.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
script="$root/.cloud/scripts/measure/memory-budget.sh"
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
		sed 's/^/     /' "$work/out"
	fi
}

# budget <file>: runs the check, keeping its output in $work/out; prints its exit status.
budget() {
	sh "$script" "$1" >"$work/out" 2>&1
	echo $?
}

# The real file.
status=$(budget "$deployment/docker-compose.yaml")
check "the deployment's default containers fit the budget" "$([ "$status" -eq 0 ] && echo ok || echo bad)"
total=$(awk '$1 == "TOTAL" { print $2 }' "$work/out")
check "the total is at most 6656 MiB (got $total)" "$([ -n "$total" ] && [ "$total" -le 6656 ] && echo ok || echo bad)"
check "the db limit leaves room for 1 GB of shared_buffers" "$(awk '$1 == "db" && $3 >= 1536 { ok = 1 } END { print (ok ? "ok" : "bad") }' "$work/out")"
check "optional components are not counted" "$(grep -qE '^(plugin-codeql|prometheus|grafana|postgres_exporter) ' "$work/out" && echo bad || echo ok)"
check "one-shot jobs are not counted" "$(grep -qE '^(migrate|knowledge-restore|default-analyzer) ' "$work/out" && echo bad || echo ok)"

check "RabbitMQ's limit is checked against rabbitmq.conf" "$(grep -q '^rabbitmq ' "$work/out" && echo ok || echo bad)"
check "RabbitMQ's watermark is relative" "$(grep -qE '^vm_memory_high_watermark\.relative *= *0\.[0-9]+$' "$deployment/config/rabbitmq.conf" && echo ok || echo bad)"

# Fixtures. svc writes a service: name, memory limit, cpus, extra service-level lines, replicas.
svc() {
	printf '  %s:\n    image: x\n' "$1"
	[ -n "$4" ] && printf '%s\n' "$4"
	printf '    deploy:\n'
	[ -n "$5" ] && printf '      replicas: %s\n' "$5"
	printf '      resources:\n        limits:\n'
	[ -n "$3" ] && printf '          cpus: "%s"\n' "$3"
	[ -n "$2" ] && printf '          memory: %s\n' "$2"
	printf '        reservations:\n          memory: 9G\n'
}

{
	echo "services:"
	svc a 6G 4
	svc b 512M 1 '    environment:
      GOMEMLIMIT: 426MiB'
	svc job 4G 1 '    restart: "no"'
	svc opt 4G 1 '    profiles: [extra]'
} >"$work/fits.yaml"
status=$(budget "$work/fits.yaml")
check "a file within the budget passes, without jobs and profiles" "$([ "$status" -eq 0 ] && grep -qx 'TOTAL 6656' "$work/out" && echo ok || echo bad)"

{
	echo "services:"
	svc a 6G 1
	svc b 256M 1 "" 3
} >"$work/replicas.yaml"
status=$(budget "$work/replicas.yaml")
check "replicas multiply the limit and can break the budget" "$([ "$status" -ne 0 ] && grep -qx 'TOTAL 6912' "$work/out" && grep -q 'over the 6656 MiB budget' "$work/out" && echo ok || echo bad)"

{
	echo "services:"
	svc a 1G 4.5
	svc opt 1G 8 '    profiles: [extra]'
} >"$work/cpus.yaml"
status=$(budget "$work/cpus.yaml")
check "a CPU limit above 4 is refused, also for optional components" "$([ "$status" -ne 0 ] && grep -q 'a: CPU limit 4.5 is above 4' "$work/out" && grep -q 'opt: CPU limit 8 is above 4' "$work/out" && echo ok || echo bad)"

{
	echo "services:"
	svc a "" 1
} >"$work/nolimit.yaml"
status=$(budget "$work/nolimit.yaml")
check "a default container without a memory limit is refused" "$([ "$status" -ne 0 ] && grep -q 'a: no memory limit' "$work/out" && echo ok || echo bad)"

{
	echo "services:"
	svc a 512M 1 '    environment:
      <<: *env
      GOMEMLIMIT: 512MiB'
} >"$work/gomem.yaml"
status=$(budget "$work/gomem.yaml")
check "a GOMEMLIMIT not below the container limit is refused" "$([ "$status" -ne 0 ] && grep -q 'a: GOMEMLIMIT 512 MiB is not below its 512 MiB limit' "$work/out" && echo ok || echo bad)"

{
	echo "services:"
	svc a 512M 1 '    environment:
      GOMEMLIMIT: 300MiB'
} >"$work/gomem-drift.yaml"
status=$(budget "$work/gomem-drift.yaml")
check "a GOMEMLIMIT far from 5/6 of the limit is refused" "$([ "$status" -ne 0 ] && grep -q 'a: GOMEMLIMIT 300 MiB is not 5/6 of its 512 MiB limit (426 MiB)' "$work/out" && echo ok || echo bad)"

# rabbitmq.conf beside the Compose file must state the rabbitmq container limit in bytes.
mkdir -p "$work/rabbit/config"
{
	echo "services:"
	svc rabbitmq 512M 1
} >"$work/rabbit/docker-compose.yaml"
echo 'total_memory_available_override_value = 536870912' >"$work/rabbit/config/rabbitmq.conf"
status=$(budget "$work/rabbit/docker-compose.yaml")
check "a rabbitmq.conf matching the rabbitmq limit passes" "$([ "$status" -eq 0 ] && echo ok || echo bad)"
echo 'total_memory_available_override_value = 268435456' >"$work/rabbit/config/rabbitmq.conf"
status=$(budget "$work/rabbit/docker-compose.yaml")
check "a rabbitmq.conf that drifted from the rabbitmq limit is refused" "$([ "$status" -ne 0 ] && grep -q 'rabbitmq: rabbitmq.conf says 268435456 bytes, its limit is 536870912' "$work/out" && echo ok || echo bad)"
rm "$work/rabbit/config/rabbitmq.conf"
status=$(budget "$work/rabbit/docker-compose.yaml")
check "a rabbitmq service without rabbitmq.conf is refused" "$([ "$status" -ne 0 ] && grep -q 'rabbitmq: no total_memory_available_override_value' "$work/out" && echo ok || echo bad)"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
