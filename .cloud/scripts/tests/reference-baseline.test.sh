#!/bin/sh
# Tests the reference-machine baseline's summary and thresholds on fixture samples; run mode is CI only.
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
# cgroup peaks: api peaked at 500 MiB between samples; db has none recorded.
echo "api,524288000" >"$out/peak.csv"

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
has "| api | 500.0 |" "api peak is its cgroup peak when that is above the samples"
has "| db | 1536.0 |" "db peak converts GiB to MiB"
has "| **Total (peak of the sum)** | **1536.5** |" "stack total is the peak of per-sample sums, with KiB converted"
has "| **Total (sum of each container's peak)** | **2036.0** |" "the sum of per-container peaks uses cgroup peaks"
has "OOM-killed containers: 1 (plugin-codeql)" "a container with oom_killed true is counted once"
has "Restarts: plugin-codeql 2" "restarts are the highest count seen"
has "| UI | 20 | 0.190 | 0 |" "UI p95 is nearest-rank (19th of 20)"
has "| API | 10 | 60.000 | 1 |" "a non-2xx API response counts as a 60 s sample and is counted"
has "| plugin-codeql | codeclarityce/plugin-codeql:latest | missing | not started |" "an image that is missing on arm64 is shown"
has "| api | codeclarityce/api:latest | arm64 | running |" "an arm64 image is shown with its arch"
has "- FAIL: plugin-codeql was killed for running out of memory" "the summary shows a failed threshold"
has "- FAIL: plugin-codeql has no arm64 image (missing)" "the summary shows an image missing on arm64"

# Thresholds. good writes a run that meets every one: 6600 MiB peak, p95 0.9 s, a completed analysis.
good() {
	d="$work/$1"
	mkdir -p "$d"
	printf 'STARTED=1000\nFINISHED=1600\nSTATUS=completed\n' >"$d/timing.env"
	printf 'epoch,container,usage\n1,db,6000MiB / 8GiB\n1,api,600MiB / 1GiB\n2,db,100MiB / 8GiB\n' >"$d/mem.csv"
	printf 'epoch,container,oom_killed,restarts\n1,db,false,0\n' >"$d/oom.csv"
	: >"$d/oom-events.csv"
	{
		echo "epoch,kind,path,status,seconds"
		i=1
		while [ "$i" -le 20 ]; do
			printf '%d,ui,/,200,0.%d\n%d,api,/org,200,0.%d\n' "$i" "$((i < 19 ? 1 : 9))" "$i" "$((i < 19 ? 1 : 9))"
			i=$((i + 1))
		done
	} >"$d/latency.csv"
	printf 'service,image,arch,state\n' >"$d/images.csv"
	echo "$d"
}

# verdict <dir> <expected exit: 0 or 1> <line that must appear> <name>
verdict() {
	sh "$script" check "$1" >"$work/check.out" 2>&1
	code=$?
	if { [ "$2" -eq 0 ] && [ "$code" -eq 0 ]; } || { [ "$2" -eq 1 ] && [ "$code" -ne 0 ]; }; then
		if grep -qF -- "$3" "$work/check.out"; then check "$4" ok; return; fi
	fi
	check "$4" bad
	sed 's/^/     /' "$work/check.out"
}

d=$(good pass)
verdict "$d" 0 "ok: the stack's peak memory, 6600.0 MiB, is within the 6656 MiB budget" "a run within every threshold passes"

d=$(good peak)
printf '3,db,7000MiB / 8GiB\n' >>"$d/mem.csv"
verdict "$d" 1 "FAIL: the stack's peak memory, 7600.0 MiB, is over the 6656 MiB budget" "a peak over 6.5 GiB fails"

# A peak between two samples is caught by the cgroup's own peak.
d=$(good cgrouppeak)
echo "db,7340032000" >"$d/peak.csv"
verdict "$d" 1 "FAIL: the stack's peak memory, 7600.0 MiB, is over the 6656 MiB budget" "a cgroup peak over the budget fails"

d=$(good non2xx)
printf '30,ui,/projects,500,0.1\n31,ui,/projects,502,0.1\n' >>"$d/latency.csv"
verdict "$d" 1 "FAIL: UI p95 latency, 60.000 s, is over 1 s" "fast non-2xx responses count as slow samples"

d=$(good noarm64)
printf 'service-knowledge,codeclarityce/service-knowledge,missing,not started\napi,codeclarityce/api,arm64,running\n' >>"$d/images.csv"
verdict "$d" 1 "FAIL: service-knowledge has no arm64 image (missing)" "a default image without arm64 fails"

d=$(good arm64)
printf 'api,codeclarityce/api,arm64,running\n' >>"$d/images.csv"
verdict "$d" 0 "ok: every default image runs on arm64" "arm64 images pass"

d=$(good oomflag)
printf '5,plugin-vuln-finder,true,1\n' >>"$d/oom.csv"
verdict "$d" 1 "FAIL: plugin-vuln-finder was killed for running out of memory" "an OOM-killed flag fails"

# The flag resets when the container restarts, so Docker's oom events count too.
d=$(good oomevent)
printf '7,codeclarity-api-1\n' >"$d/oom-events.csv"
verdict "$d" 1 "FAIL: codeclarity-api-1 was killed for running out of memory" "an oom event fails"

d=$(good uip95)
printf '30,ui,/projects,200,1.5\n31,ui,/projects,200,1.5\n' >>"$d/latency.csv"
verdict "$d" 1 "FAIL: UI p95 latency, 1.500 s, is over 1 s" "a UI p95 over 1 s fails"

d=$(good apip95)
printf '30,api,/org,000,60.0\n31,api,/org,000,60.0\n' >>"$d/latency.csv"
verdict "$d" 1 "FAIL: API p95 latency, 60.000 s, is over 1 s" "an API p95 over 1 s fails, timeouts included"

d=$(good nolatency)
printf 'epoch,kind,path,status,seconds\n' >"$d/latency.csv"
verdict "$d" 1 "FAIL: no UI latency was recorded" "no latency samples fails"

d=$(good unfinished)
printf 'STARTED=1000\nFINISHED=0\nSTATUS=timeout\n' >"$d/timing.env"
verdict "$d" 1 "FAIL: the analysis did not finish (status timeout)" "an unfinished analysis fails"

d=$(good failedstep)
echo '{"data":{"status":"completed","steps":[[{"Name":"js-sbom","Status":"success"},{"Name":"vuln-finder","Status":"failure"}]]}}' >"$d/analysis.json"
verdict "$d" 1 "FAIL: the analysis did not finish (status completed, a step did not succeed)" "a completed analysis with a failed step fails"

# The upload tarball holds the baseline project's manifest and lockfile by their real names.
if sh "$script" tarball "$root/.cloud/scripts/measure/baseline-project" "$work/app.tar.gz" >"$work/tarball.out" 2>&1; then
	listing=$(tar -tzf "$work/app.tar.gz" | sort | tr '\n' ' ')
else
	listing=$(cat "$work/tarball.out")
fi
check "the upload tarball has package.json and package-lock.json by their real names" \
	"$([ "$listing" = "package-lock.json package.json " ] && echo ok || echo bad)"
[ "$listing" = "package-lock.json package.json " ] || echo "     got: $listing"

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
