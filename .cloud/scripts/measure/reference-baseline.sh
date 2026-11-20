#!/bin/sh
# Measures the default production stack on a real npm analysis and fails on the reference-machine thresholds.
# Usage: sh .cloud/scripts/measure/reference-baseline.sh run|summarize|check <out-dir>
#        sh .cloud/scripts/measure/reference-baseline.sh tarball <project-dir> <out-file>
# run needs an empty Docker daemon and never removes anything; summarize and check only read <out-dir>.
# tarball writes the upload tarball run sends for <project-dir>.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

usage() {
	echo "usage: $0 run <out-dir> | summarize <out-dir> | check <out-dir> | tarball <project-dir> <out-file>" >&2
	exit 2
}

# Writes the upload tarball of project $1 to $2. The baseline project stores its files with a .fixture
# suffix so GitHub does not scan them; the tarball gets their real names.
tarball() {
	staging=$(mktemp -d)
	for f in package.json package-lock.json; do
		if [ -f "$1/$f.fixture" ]; then cp "$1/$f.fixture" "$staging/$f"; else cp "$1/$f" "$staging/$f"; fi
	done
	tar -czf "$2" -C "$staging" package.json package-lock.json
	rm -rf "$staging"
}

# Prints each container's peak memory in MiB, sorted, then TOTAL (peak of per-sample sums) and SUM (sum of
# each container's peak). $2, if present, holds cgroup peaks as "container,bytes", which win when higher.
memory_table() {
	awk -F, '
	function tobytes(s,   n, u) {
		n = s + 0
		u = s
		sub(/^[0-9.]+/, "", u)
		if (u == "B") return n
		if (u == "kB" || u == "KB") return n * 1000
		if (u == "KiB") return n * 1024
		if (u == "MB") return n * 1000000
		if (u == "MiB") return n * 1048576
		if (u == "GB") return n * 1000000000
		if (u == "GiB") return n * 1073741824
		if (u == "TB") return n * 1000000000000
		if (u == "TiB") return n * 1099511627776
		print "unknown memory unit: " s > "/dev/stderr"
		exit 1
	}
	FILENAME != ARGV[1] { if ($2 + 0 > peak[$1]) peak[$1] = $2 + 0; next }
	$1 == "epoch" { next }
	{
		split($3, part, " / ")
		v = tobytes(part[1])
		if (v > peak[$2]) peak[$2] = v
		sum[$1] += v
		if (sum[$1] > total) total = sum[$1]
	}
	END {
		for (c in peak) { printf "%s\t%.1f\n", c, peak[c] / 1048576 | "sort"; all += peak[c] }
		close("sort")
		printf "TOTAL\t%.1f\n", total / 1048576
		printf "SUM\t%.1f\n", all / 1048576
	}' "$1" ${2:+"$2"}
}

# Prints the cgroup peaks file of $1 if run wrote one.
peaks_file() {
	if [ -s "$1/peak.csv" ]; then echo "$1/peak.csv"; fi
}

# Prints the seconds of the latency samples of kind $2 in $1; a non-2xx response counts as 60 s.
latencies() {
	awk -F, -v k="$2" '$1 != "epoch" && $2 == k { print ($4 ~ /^2/ ? $5 : (($5 + 0) > 60 ? $5 : 60)) }' "$1"
}

# Prints the 95th percentile (nearest rank) of the numbers on stdin, or n/a.
p95() {
	sort -n | awk '{ v[NR] = $1 } END {
		if (NR == 0) { print "n/a"; exit }
		r = int(0.95 * NR)
		if (r < 0.95 * NR) r++
		if (r < 1) r = 1
		printf "%.3f", v[r]
	}'
}

# Prints "ok: ..." or "FAIL: ..." for each threshold on the samples in $1.
# shellcheck disable=SC2153 # STATUS comes from the sourced timing.env
thresholds() {
	tdir=$1
	# shellcheck disable=SC1091 # written by run
	. "$tdir/timing.env"
	budget=${BUDGET_MIB:-6656}
	limit=${P95_LIMIT_SECONDS:-1}

	# The OOM-killed flag resets when a container restarts, so Docker's oom events count too.
	killed=$({
		awk -F, '$1 != "epoch" && $3 == "true" { print $2 }' "$tdir/oom.csv"
		if [ -f "$tdir/oom-events.csv" ]; then awk -F, 'NF >= 2 && $2 != "" { print $2 }' "$tdir/oom-events.csv"; fi
	} | sort -u)
	if [ -z "$killed" ]; then
		echo "ok: no container was killed for running out of memory"
	else
		echo "$killed" | sed 's/^/FAIL: /; s/$/ was killed for running out of memory/'
	fi

	if [ "$(awk -F, '$1 != "epoch"' "$tdir/mem.csv" | wc -l)" -eq 0 ]; then
		echo "FAIL: no memory use was recorded"
	else
		peak=$(memory_table "$tdir/mem.csv" "$(peaks_file "$tdir")" | awk -F'\t' '$1 == "SUM" { print $2 }')
		if awk -v p="$peak" -v b="$budget" 'BEGIN { exit !(p + 0 <= b + 0) }'; then
			echo "ok: the stack's peak memory, $peak MiB, is within the $budget MiB budget"
		else
			echo "FAIL: the stack's peak memory, $peak MiB, is over the $budget MiB budget"
		fi
	fi

	for tkind in UI API; do
		tlower=$(echo "$tkind" | tr '[:upper:]' '[:lower:]')
		p=$(latencies "$tdir/latency.csv" "$tlower" | p95)
		if [ "$p" = n/a ]; then
			echo "FAIL: no $tkind latency was recorded"
		elif awk -v p="$p" -v l="$limit" 'BEGIN { exit !(p + 0 <= l + 0) }'; then
			echo "ok: $tkind p95 latency, $p s, is within $limit s"
		else
			echo "FAIL: $tkind p95 latency, $p s, is over $limit s"
		fi
	done

	noarm=$(awk -F, '$1 != "service" && $3 != "arm64" { print $1 " has no arm64 image (" $3 ")" }' "$tdir/images.csv" 2>/dev/null)
	if [ -z "$noarm" ]; then
		echo "ok: every default image runs on arm64"
	else
		echo "$noarm" | sed 's/^/FAIL: /'
	fi

	if [ "${STATUS:-}" != completed ]; then
		echo "FAIL: the analysis did not finish (status ${STATUS:-unknown})"
	elif [ -f "$tdir/analysis.json" ] && ! jq -e '[.data.steps[][] | .Status] | length > 0 and all(. == "success" or . == "skipped")' "$tdir/analysis.json" >/dev/null 2>&1; then
		echo "FAIL: the analysis did not finish (status completed, a step did not succeed)"
	else
		echo "ok: the analysis finished"
	fi
}

# Prints the markdown summary of the samples in $1 and writes it to $1/summary.md.
# shellcheck disable=SC2153 # STATUS and STARTED come from the sourced timing.env
summarize() {
	# Not dir: sh has no local, and run's compose reads dir after this.
	sdir=$1
	[ -f "$sdir/timing.env" ] || { echo "summarize: no $sdir/timing.env" >&2; return 1; }
	# shellcheck disable=SC1091 # written by run
	. "$sdir/timing.env"
	md="$sdir/summary.md"
	{
		echo "## Reference-machine baseline (arm64)"
		echo
		if [ "${FINISHED:-0}" -gt 0 ]; then
			echo "Analysis: **${STATUS}** in $((FINISHED - STARTED)) s (from submission to a final status)."
		else
			echo "Analysis: **${STATUS:-unknown}**; no final status was reached."
		fi
		echo
		echo "### Memory (peak, MiB)"
		echo
		echo "| Container | Peak MiB |"
		echo "|---|---|"
		mt=$(memory_table "$sdir/mem.csv" "$(peaks_file "$sdir")")
		echo "$mt" | awk -F'\t' '$1 == "TOTAL" || $1 == "SUM" { next } { print "| " $1 " | " $2 " |" }'
		echo "| **Total (peak of the sum)** | **$(echo "$mt" | awk -F'\t' '$1 == "TOTAL" { print $2 }')** |"
		echo "| **Total (sum of each container's peak)** | **$(echo "$mt" | awk -F'\t' '$1 == "SUM" { print $2 }')** |"
		echo
		echo "### OOM kills and restarts"
		echo
		killed=$(awk -F, '$1 != "epoch" && $3 == "true" { k[$2] = 1 } END { for (c in k) print c }' "$sdir/oom.csv" | sort | paste -sd, - | sed 's/,/, /g')
		echo "OOM-killed containers: $(awk -F, '$1 != "epoch" && $3 == "true" { k[$2] = 1 } END { print length(k) + 0 }' "$sdir/oom.csv")${killed:+ ($killed)}"
		restarts=$(awk -F, '$1 != "epoch" { if ($4 + 0 > r[$2]) r[$2] = $4 + 0 } END { for (c in r) if (r[c] > 0) printf "%s %d\n", c, r[c] }' "$sdir/oom.csv" | sort)
		if [ -n "$restarts" ]; then
			echo "Restarts: $(echo "$restarts" | awk '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }')"
		else
			echo "Restarts: none"
		fi
		echo
		echo "### Latency while the analysis ran (p95, seconds)"
		echo
		echo "| Kind | Requests | p95 s | Non-2xx |"
		echo "|---|---|---|---|"
		for kind in UI API; do
			lower=$(echo "$kind" | tr '[:upper:]' '[:lower:]')
			seconds=$(latencies "$sdir/latency.csv" "$lower")
			count=$(awk -F, -v k="$lower" '$1 != "epoch" && $2 == k' "$sdir/latency.csv" | wc -l | tr -d ' ')
			bad=$(awk -F, -v k="$lower" '$1 != "epoch" && $2 == k && $4 !~ /^2/ { n++ } END { print n + 0 }' "$sdir/latency.csv")
			echo "| $kind | $count | $(echo "$seconds" | p95) | $bad |"
		done
		echo
		echo "### Images on arm64"
		echo
		echo "| Service | Image | Arch | State |"
		echo "|---|---|---|---|"
		awk -F, '$1 != "service" { print "| " $1 " | " $2 " | " $3 " | " $4 " |" }' "$sdir/images.csv"
		echo
		echo "### Thresholds"
		echo
		thresholds "$sdir" | sed 's/^/- /'
	} >"$md"
	cat "$md"
}

# Prints what keeps the stack from being ready: a job not exited 0, or a service not running and healthy.
pending() {
	for j in $JOBS; do
		awk -v s="$j" '$1 == s && $2 == "exited" && $3 == "0" { ok = 1 } END { exit !ok }' "$work/states" || echo "job $j"
	done
	for s in $ANALYSIS_SERVICES; do
		awk -v s="$s" '$1 == s && $2 == "running" && ($4 == "healthy" || $4 == "") { ok = 1 } END { exit !ok }' "$work/states" || echo "service $s"
	done
}

# Writes "service state exitcode health" for every container to $work/states.
states() {
	compose ps -a --format json | jq -rs 'flatten | .[] | "\(.Service) \(.State) \(.ExitCode) \(.Health // "")"' >"$work/states"
}

# Samples every container's memory use, one docker stats call per tick.
sample_memory() {
	while :; do
		ts=$(date +%s)
		docker stats --no-stream --format '{{.Name}},{{.MemUsage}}' | sed "s/^/$ts,/" >>"$out/mem.csv" || true
		sleep "$SAMPLE_SECONDS"
	done
}

# Samples each container's OOM-killed flag and restart count.
sample_oom() {
	while :; do
		ts=$(date +%s)
		# shellcheck disable=SC2086 # the container IDs, one per word
		docker inspect -f '{{.Name}},{{.State.OOMKilled}},{{.RestartCount}}' $ids | sed "s/^/$ts,/; s/,\//,/" >>"$out/oom.csv" || true
		sleep 5
	done
}

# Times one GET: epoch, kind, path, then the HTTP status and seconds (000 if the request failed).
probe() {
	# A failed or timed-out request keeps its time, so it counts against p95.
	line=$(api_curl -sS -o /dev/null --max-time 60 -H "Authorization: Bearer $token" -w '%{http_code} %{time_total}' "$4" 2>/dev/null) || :
	[ -n "$line" ] || line="000 60"
	echo "$1,$2,$3,$line" | tr ' ' ',' >>"$out/latency.csv"
}

# Times the projects page with the API call it makes, and other API calls, once a second.
sample_latency() {
	while :; do
		ts=$(date +%s)
		probe "$ts" ui /projects "$URL/projects"
		probe "$ts" ui /projects-list "$API_BASE/org/$org/projects?page=0&entries_per_page=20"
		probe "$ts" api /org "$API_BASE/org?page=0&entries_per_page=50"
		probe "$ts" api /analyzers "$API_BASE/org/$org/analyzers?page=0&entries_per_page=100"
		probe "$ts" api /analysis "$API_BASE/org/$org/projects/$project_id/analyses/$analysis"
		sleep 1
	done
}

# Writes each container's cgroup memory peak as "container,bytes", for peaks between samples.
cgroup_peaks() {
	# shellcheck disable=SC2086 # the container IDs, one per word
	docker inspect -f '{{.Id}} {{.Name}}' $ids | while read -r id name; do
		for f in "/sys/fs/cgroup/system.slice/docker-$id.scope/memory.peak" "/sys/fs/cgroup/docker/$id/memory.peak" \
			"/sys/fs/cgroup/memory/docker/$id/memory.max_usage_in_bytes" \
			"/sys/fs/cgroup/memory/system.slice/docker-$id.scope/memory.max_usage_in_bytes"; do
			if [ -r "$f" ]; then
				echo "${name#/},$(cat "$f")"
				break
			fi
		done
	done
}

stop_samplers() {
	for p in $pids; do kill "$p" 2>/dev/null || true; done
	pids=""
}

# Copies Caddy's internal CA to $CURL_CA once Caddy has made it.
fetch_ca() {
	deadline=$(($(date +%s) + 120))
	until compose exec -T frontend cat /data/caddy/pki/authorities/local/root.crt >"$CURL_CA" 2>/dev/null && [ -s "$CURL_CA" ]; do
		[ "$(date +%s)" -lt "$deadline" ] || return 1
		sleep 2
	done
}

run() {
	out=$1
	mkdir -p "$out"
	out=$(cd "$out" && pwd)
	work=$(mktemp -d)
	pids=""
	trap 'stop_samplers; rm -rf "$work"' EXIT

	dir=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
	project=$(cd "${PROJECT_DIR:-$here/baseline-project}" && pwd)
	DOMAIN=localhost
	export DOMAIN
	URL="https://$DOMAIN"
	EMAIL=operator@example.com
	NAME="Reference Machine"
	CREATE_USER_PASSWORD="baseline-$(date +%s)"
	export CREATE_USER_PASSWORD
	ANALYZER="Default Analyzer"
	JOBS="version-check generate-secrets knowledge-restore migrate default-analyzer vulnerability-instance-backfill"
	ANALYSIS_SERVICES="service-dispatcher service-downloader service-follower plugin-js-sbom plugin-php-sbom plugin-vuln-finder plugin-license-finder api"
	WAIT_SECONDS=${WAIT_SECONDS:-3000}
	ANALYSIS_WAIT_SECONDS=${ANALYSIS_WAIT_SECONDS:-2400}
	SAMPLE_SECONDS=${SAMPLE_SECONDS:-2}
	API_BASE="$URL/api"
	CURL_CA="$work/ca.crt"
	LOGIN_EMAIL=$EMAIL
	LOGIN_PASSWORD=$CREATE_USER_PASSWORD
	LOGIN_WAIT_SECONDS=300
	WORK=$work
	: >"$out/mem.csv"
	: >"$out/oom.csv"
	: >"$out/latency.csv"
	: >"$out/oom-events.csv"
	echo "epoch,container,usage" >>"$out/mem.csv"
	echo "epoch,container,oom_killed,restarts" >>"$out/oom.csv"
	echo "epoch,kind,path,status,seconds" >>"$out/latency.csv"
	# The version the released Compose file runs, as the production fresh-install test sets it.
	CODECLARITY_VERSION=$(jq -er .version "$dir/config.json")
	export CODECLARITY_VERSION

	compose() {
		docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" "$@"
	}

	# shellcheck source=../tests/fresh-install/lib.sh
	. "$root/.cloud/scripts/tests/fresh-install/lib.sh"

	if [ -n "$(compose ps -aq)" ]; then
		echo "reference-baseline: a stack already exists on this daemon; this needs an empty one" >&2
		exit 1
	fi

	# An image without an arm64 variant stays missing, its service is not started, and the run fails.
	# Images already on the daemon, such as the ones CI built from the submodules, are not pulled.
	compose config --format json >"$work/config.json"
	jq -r '.services | to_entries[] | "\(.key) \(.value.image // "-")"' "$work/config.json" >"$work/services.txt"
	to_pull=$(while read -r service image; do
		docker image inspect "$image" >/dev/null 2>&1 || echo "$service"
	done <"$work/services.txt")
	# shellcheck disable=SC2086 # the service names, one per word
	if [ -n "$to_pull" ]; then compose pull --ignore-pull-failures $to_pull >"$out/pull.log" 2>&1 || true; fi
	: >"$work/arch.txt"
	while read -r service image; do
		arch=$(docker image inspect -f '{{.Architecture}}' "$image" 2>/dev/null) || arch=missing
		echo "$service $image $arch" >>"$work/arch.txt"
		if [ "$arch" != arm64 ]; then echo "::error::reference-baseline: $service has no arm64 image ($image: $arch)" >&2; fi
	done <"$work/services.txt"
	# shellcheck disable=SC2046 # the service names, one per word
	compose up -d $(awk '$3 != "missing" { print $1 }' "$work/arch.txt")

	ready=0
	deadline=$(($(date +%s) + WAIT_SECONDS))
	while :; do
		states
		if [ -z "$(pending)" ]; then ready=1; break; fi
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep 5
	done
	if [ "$ready" -ne 1 ]; then
		echo "reference-baseline: the stack did not settle; still pending:" >&2
		pending >&2
		compose ps -a >&2 || true
		exit 1
	fi

	compose run --rm -T -e CREATE_USER_PASSWORD api create-user --email "$EMAIL" --name "$NAME" >/dev/null
	fetch_ca
	wait_for_login
	if [ -z "$token" ]; then echo "reference-baseline: login failed" >&2; exit 1; fi
	org=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)][0].organization.id')
	project_id=$(post "/org/$org/projects" '{"name":"reference-machine-baseline","description":"Reference-machine baseline (#162)"}' | jq -er '.id')
	tarball "$project" "$work/app.tar.gz"
	api_curl -fsS -X PATCH "$API_BASE/org/$org/file/$project_id/upload" -H "Authorization: Bearer $token" \
		--form-string type=source --form-string file_name=app.tar.gz --form-string chunk=true \
		--form-string id=0 --form-string last=true --form-string "hash=$(sha256sum "$work/app.tar.gz" | cut -d' ' -f1)" \
		-F "file=@$work/app.tar.gz;filename=app.tar.gz" >/dev/null
	analyzer=$(get "/org/$org/analyzers?page=0&entries_per_page=100" | jq -er --arg n "$ANALYZER" '[.data[] | select(.name == $n)][0].id')
	project_path="$org/projects/$project_id/main"
	body='{"analyzer_id":"'"$analyzer"'","branch":"main","config":{"js-sbom":{"branch":"main","project":"'"$project_path"'"},"php-sbom":{"branch":"main","project":"'"$project_path"'"},"vuln-finder":{"vulnerabilityPolicy":[]},"license-finder":{"licensePolicy":[]}}}'

	# The samplers cover the analysis, from submission to a final status.
	started=$(date +%s)
	analysis=$(post "/org/$org/projects/$project_id/analyses" "$body" | jq -er '.id')
	ids=$(compose ps -aq)
	docker events --filter type=container --filter event=oom --format '{{.Time}},{{.Actor.Attributes.name}}' >>"$out/oom-events.csv" &
	pids="$pids $!"
	sample_memory &
	pids="$pids $!"
	sample_oom &
	pids="$pids $!"
	sample_latency &
	pids="$pids $!"

	deadline=$(($(date +%s) + ANALYSIS_WAIT_SECONDS))
	status=timeout
	while :; do
		get "/org/$org/projects/$project_id/analyses/$analysis" >"$work/analysis.json" 2>/dev/null || :
		s=$(jq -r '.data.status // empty' "$work/analysis.json" 2>/dev/null) || s=
		case "$s" in completed | failure | cancelled) status=$s; break ;; esac
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep 10
	done
	finished=$(date +%s)
	stop_samplers
	cgroup_peaks >"$out/peak.csv" || :
	if [ ! -s "$out/peak.csv" ]; then echo "reference-baseline: no cgroup memory peaks found, using sampled peaks" >&2; fi
	[ "$status" = timeout ] && finished=0

	cp "$work/analysis.json" "$out/analysis.json" 2>/dev/null || echo '{}' >"$out/analysis.json"
	printf 'STARTED=%s\nFINISHED=%s\nSTATUS=%s\n' "$started" "$finished" "$status" >"$out/timing.env"

	states
	{
		echo "service,image,arch,state"
		while read -r service image arch; do
			state=$(awk -v s="$service" '$1 == s { print $2 }' "$work/states")
			echo "$service,$image,$arch,${state:-not started}"
		done <"$work/arch.txt"
	} >"$out/images.csv"

	summarize "$out" >/dev/null

	fails=$(thresholds "$out" | grep '^FAIL' || :)
	if [ -z "$fails" ]; then
		echo "reference-baseline: every threshold met"
		return 0
	fi
	echo "$fails" | sed 's/^/reference-baseline: /' >&2
	if echo "$fails" | grep -q 'analysis did not finish'; then
		# shellcheck disable=SC2086 # a list of service names
		report $ANALYSIS_SERVICES
	fi
	return 1
}

case "${1:-}" in
run)
	[ $# -eq 2 ] || usage
	run "$2"
	;;
summarize)
	[ $# -eq 2 ] || usage
	summarize "$2"
	;;
tarball)
	[ $# -eq 3 ] || usage
	tarball "$2" "$3"
	;;
check)
	[ $# -eq 2 ] || usage
	[ -f "$2/timing.env" ] || { echo "check: no $2/timing.env" >&2; exit 1; }
	results=$(thresholds "$2")
	echo "$results"
	! echo "$results" | grep -q '^FAIL'
	;;
*) usage ;;
esac
