#!/bin/sh
# Checks a Compose file's default containers: memory limits within BUDGET_MIB (6656, 6.5 GiB), CPU limits
# at most MAX_CPUS (4), GOMEMLIMIT at 5/6 of each limit, and rabbitmq.conf matching the rabbitmq limit.
# Usage: sh .cloud/scripts/measure/memory-budget.sh <docker-compose.yaml>
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <docker-compose.yaml>" >&2; exit 2; }
[ -f "$1" ] || { echo "memory-budget: no file $1" >&2; exit 2; }

# Reads the block layout of the Compose file; it handles the two-space indentation this repo uses.
awk -v budget="${BUDGET_MIB:-6656}" -v maxcpus="${MAX_CPUS:-4}" -v conf="$(dirname "$1")/config/rabbitmq.conf" '
function unquote(v) {
	sub(/^[ \t]+/, "", v); sub(/[ \t]+(#.*)?$/, "", v)
	gsub(/^["\047]|["\047]$/, "", v)
	return v
}
# Compose memory units are binary: b, k, m, g, with an optional trailing b.
function mib(v,   n, u) {
	v = tolower(v)
	n = v + 0
	u = v
	sub(/^[0-9.]+/, "", u)
	sub(/b$/, "", u); if (v ~ /^[0-9.]+b$/) u = "b"
	sub(/i$/, "", u)
	if (u == "b" || u == "") return n / 1048576
	if (u == "k") return n / 1024
	if (u == "m") return n
	if (u == "g") return n * 1024
	print "memory-budget: unknown memory unit: " v > "/dev/stderr"
	bad = 1
	return 0
}
{ sub(/\r$/, "") }
# Lines inside a block scalar (key: |) are text, not keys.
blockindent >= 0 {
	match($0, /^ */)
	if ($0 ~ /^ *$/ || RLENGTH > blockindent) next
	blockindent = -1
}
/^ *(#.*)?$/ { next }
{
	match($0, /^ */)
	ind = RLENGTH
	line = substr($0, ind + 1)
	if (line ~ /^-/) next
	if (line !~ /^[^:]+:/) next
	key = line; sub(/:.*/, "", key)
	val = line; sub(/^[^:]+:/, "", val)
	k[ind] = key
	for (i = ind + 1; i <= 20; i++) delete k[i]
	if (val ~ /^[ \t]*[|>][-+]?[ \t]*$/) blockindent = ind
	if (ind == 0) { inservices = (key == "services"); next }
	if (!inservices) next
	if (ind == 2) { svc = key; order[++n] = svc; replicas[svc] = 1; next }
	if (ind == 4 && key == "profiles") optional[svc] = 1
	if (ind == 4 && key == "restart" && unquote(val) == "no") job[svc] = 1
	if (ind == 6 && k[4] == "deploy" && key == "replicas") replicas[svc] = unquote(val) + 0
	if (ind == 6 && k[4] == "environment" && key == "GOMEMLIMIT") gomem[svc] = mib(unquote(val))
	if (ind == 10 && k[4] == "deploy" && k[6] == "resources" && k[8] == "limits") {
		if (key == "memory") memory[svc] = mib(unquote(val))
		if (key == "cpus") cpus[svc] = unquote(val)
	}
}
BEGIN { blockindent = -1 }
END {
	for (i = 1; i <= n; i++) {
		s = order[i]
		if (s in cpus && cpus[s] + 0 > maxcpus + 0) { print s ": CPU limit " cpus[s] " is above " maxcpus; bad = 1 }
		if ((s in gomem) && (s in memory) && gomem[s] >= memory[s]) {
			printf "%s: GOMEMLIMIT %d MiB is not below its %d MiB limit\n", s, gomem[s], memory[s]; bad = 1
		} else if ((s in gomem) && (s in memory) && (gomem[s] < int(memory[s] * 5 / 6) - 1 || gomem[s] > int(memory[s] * 5 / 6) + 1)) {
			printf "%s: GOMEMLIMIT %d MiB is not 5/6 of its %d MiB limit (%d MiB)\n", s, gomem[s], memory[s], int(memory[s] * 5 / 6); bad = 1
		}
		if (optional[s] || job[s]) continue
		if (!(s in memory)) { print s ": no memory limit"; bad = 1; continue }
		printf "%s %d %d %s\n", s, replicas[s], memory[s], (s in cpus ? cpus[s] : "-")
		total += replicas[s] * memory[s]
	}
	if ("rabbitmq" in memory) {
		override = ""
		while ((getline l < conf) > 0) {
			if (l ~ /^total_memory_available_override_value *=/) { override = l; sub(/^[^=]*= */, "", override); sub(/[ \t]+$/, "", override) }
		}
		want = sprintf("%d", memory["rabbitmq"] * 1048576)
		if (override == "") { print "rabbitmq: no total_memory_available_override_value in " conf; bad = 1 }
		else if (override != want) { print "rabbitmq: rabbitmq.conf says " override " bytes, its limit is " want; bad = 1 }
	}
	printf "TOTAL %d\n", total
	if (total > budget) { printf "memory limits add up to %d MiB, over the %d MiB budget\n", total, budget; bad = 1 }
	exit bad
}' "$1"
