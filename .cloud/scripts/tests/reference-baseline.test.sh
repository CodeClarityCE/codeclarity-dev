#!/bin/sh
# Tests the reference-machine baseline's summary on fixture samples: peak memory per container and
# in total (with mixed units), OOM kills and restarts, p95 latency with nearest-rank, analysis time,
# and the arm64 image table. The run mode needs a Docker daemon and is checked by CI, not here.
# Usage: sh .cloud/scripts/tests/reference-baseline.test.sh
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
script="$root/.cloud/scripts/measure/reference-baseline.sh"

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
	fi
}

out="$work/run"
mkdir -p "$out"
printf 'STARTED=1000\nFINISHED=1600\nSTATUS=completed\n' >"$out/timing.env"

# Memory: api peaks at 300 MiB; db peaks at 1.5 GiB; the stack peaks at epoch 3 (1536.5 MiB).
{
	echo "epoch,container,usage"
	echo "1,api,100.0MiB / 1GiB"
	echo "1,db,1.0GiB / 2GiB"
	echo "2,api,300.0MiB / 1GiB"
	echo "2,db,1.0GiB / 2GiB"
	echo "3,api,512KiB / 1GiB"
	echo "3,db,1.5GiB / 2GiB"
} >"$out/mem.csv"

{
	echo "epoch,container,oom_killed,restarts"
	echo "1,api,false,0"
	echo "2,plugin-codeql,true,1"
	echo "3,plugin-codeql,false,2"
} >"$out/oom.csv"

# Latency: 20 UI samples 0.01 to 0.20 s (p95 is the 19th, 0.190); 10 API samples, one a 500.
{
	echo "epoch,kind,path,status,seconds"
	i=1
	while [ "$i" -le 20 ]; do
		printf '%d,ui,/,200,0.%02d\n' "$i" "$i"
		i=$((i + 1))
	done
	i=1
	while [ "$i" -le 10 ]; do
		status=200
		[ "$i" -eq 1 ] && status=500
		printf '%d,api,/org,%s,%d.%d\n' "$i" "$status" "$((i / 10))" "$((i % 10))"
		i=$((i + 1))
	done
} >"$out/latency.csv"

{
	echo "service,image,arch,state"
	echo "api,codeclarityce/api:latest,arm64,running"
	echo "plugin-codeql,codeclarityce/plugin-codeql:latest,missing,not started"
} >"$out/images.csv"

sh "$script" summarize "$out" >"$work/stdout" 2>"$work/stderr"
md="$out/summary.md"

has() {
	if grep -qxF -- "$1" "$md"; then check "$2" ok; else check "$2" bad; fi
}

check "summarize exits 0" "$([ -s "$md" ] && echo ok || echo bad)"
has "Analysis: **completed** in 600 s (from submission to a final status)." "analysis time is final minus submission"
has "| api | 300.0 |" "api peak is the largest sample in MiB"
has "| db | 1536.0 |" "db peak converts GiB to MiB"
has "| **Total (peak of the sum)** | **1536.5** |" "stack total is the peak of per-sample sums, with KiB converted"
has "OOM-killed containers: 1 (plugin-codeql)" "a container with oom_killed true is counted once"
has "Restarts: plugin-codeql 2" "restarts are the highest count seen"
has "| UI | 20 | 0.190 | 0 |" "UI p95 is nearest-rank (19th of 20)"
has "| API | 10 | 1.000 | 1 |" "API p95 is nearest-rank (10th of 10) and non-2xx are counted"
has "| plugin-codeql | codeclarityce/plugin-codeql:latest | missing | not started |" "an image that is missing on arm64 is shown"
has "| api | codeclarityce/api:latest | arm64 | running |" "an arm64 image is shown with its arch"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
