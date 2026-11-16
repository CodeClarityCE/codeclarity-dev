#!/bin/sh
# Reference-machine baseline (#162): runs the default production stack on a real npm analysis and
# records peak memory per container and in total, OOM kills and restarts, p95 latency of UI pages and
# API calls while it runs, analysis time, and each default image's arch. The run fails (#169) if a
# container is killed for running out of memory, the stack's peak is over the budget, UI or API p95
# latency is over the limit, or the analysis does not finish. Analysis time is only recorded.
#
# Usage: sh .cloud/scripts/measure/reference-baseline.sh run <out-dir>
#        sh .cloud/scripts/measure/reference-baseline.sh summarize <out-dir>
#        sh .cloud/scripts/measure/reference-baseline.sh check <out-dir>
# run needs an empty Docker daemon (CI) and never removes anything. It writes the samples, the
# analysis and timing.env to <out-dir>, then summary.md. summarize and check only read <out-dir>;
# check prints each threshold and exits 1 if one is not met.
# Env: DEPLOYMENT_DIR (default: the deployment submodule), PROJECT_DIR (default: the baseline project
#      next to this script), WAIT_SECONDS (default 3000), ANALYSIS_WAIT_SECONDS (default 2400),
#      SAMPLE_SECONDS (default 2), BUDGET_MIB (default 6656, which is 6.5 GiB),
#      P95_LIMIT_SECONDS (default 1).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)

usage() {
	echo "usage: $0 run <out-dir> | summarize <out-dir> | check <out-dir>" >&2
	exit 2
}

# Prints the table of peak memory per container, sorted, then the stack total (peak of per-sample sums).
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
	$1 == "epoch" { next }
	{
		split($3, part, " / ")
		v = tobytes(part[1])
		if (v > peak[$2]) peak[$2] = v
		sum[$1] += v
		if (sum[$1] > total) total = sum[$1]
	}
	END {
		for (c in peak) printf "%s\t%.1f\n", c, peak[c] / 1048576 | "sort"
		close("sort")
		printf "TOTAL\t%.1f\n", total / 1048576
	}' "$1"
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
		peak=$(memory_table "$tdir/mem.csv" | awk -F'\t' '$1 == "TOTAL" { print $2 }')
		if awk -v p="$peak" -v b="$budget" 'BEGIN { exit !(p + 0 <= b + 0) }'; then
			echo "ok: the stack's peak memory, $peak MiB, is within the $budget MiB budget"
		else
			echo "FAIL: the stack's peak memory, $peak MiB, is over the $budget MiB budget"
		fi
	fi

	for tkind in UI API; do
		tlower=$(echo "$tkind" | tr 'A-Z' 'a-z')
		p=$(awk -F, -v k="$tlower" '$1 != "epoch" && $2 == k { print $5 }' "$tdir/latency.csv" | p95)
		if [ "$p" = n/a ]; then
			echo "FAIL: no $tkind latency was recorded"
		elif awk -v p="$p" -v l="$limit" 'BEGIN { exit !(p + 0 <= l + 0) }'; then
			echo "ok: $tkind p95 latency, $p s, is within $limit s"
		else
			echo "FAIL: $tkind p95 latency, $p s, is over $limit s"
		fi
	done

	if [ "${STATUS:-}" != completed ]; then
		echo "FAIL: the analysis did not finish (status ${STATUS:-unknown})"
	elif [ -f "$tdir/analysis.json" ] && ! jq -e '[.data.steps[][] | .Status // .status] | length > 0 and all(. == "success" or . == "skipped")' "$tdir/analysis.json" >/dev/null 2>&1; then
		echo "FAIL: the analysis did not finish (status completed, a step did not succeed)"
	else
		echo "ok: the analysis finished"
	fi
}

# Prints the markdown summary of the samples in $1 and writes it to $1/summary.md.
summarize() {
	dir=$1
	[ -f "$dir/timing.env" ] || { echo "summarize: no $dir/timing.env" >&2; return 1; }
	# shellcheck disable=SC1091 # written by run
	. "$dir/timing.env"
	md="$dir/summary.md"
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
		memory_table "$dir/mem.csv" | awk -F'\t' '$1 == "TOTAL" { next } { print "| " $1 " | " $2 " |" }'
		echo "| **Total (peak of the sum)** | **$(memory_table "$dir/mem.csv" | awk -F'\t' '$1 == "TOTAL" { print $2 }')** |"
		echo
		echo "### OOM kills and restarts"
		echo
		killed=$(awk -F, '$1 != "epoch" && $3 == "true" { k[$2] = 1 } END { for (c in k) print c }' "$dir/oom.csv" | sort | paste -sd, - | sed 's/,/, /g')
		echo "OOM-killed containers: $(awk -F, '$1 != "epoch" && $3 == "true" { k[$2] = 1 } END { print length(k) + 0 }' "$dir/oom.csv")${killed:+ ($killed)}"
		restarts=$(awk -F, '$1 != "epoch" { if ($4 + 0 > r[$2]) r[$2] = $4 + 0 } END { for (c in r) if (r[c] > 0) printf "%s %d\n", c, r[c] }' "$dir/oom.csv" | sort)
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
			lower=$(echo "$kind" | tr 'A-Z' 'a-z')
			seconds=$(awk -F, -v k="$lower" '$1 != "epoch" && $2 == k { print $5 }' "$dir/latency.csv")
			count=$(awk -F, -v k="$lower" '$1 != "epoch" && $2 == k' "$dir/latency.csv" | wc -l | tr -d ' ')
			bad=$(awk -F, -v k="$lower" '$1 != "epoch" && $2 == k && $4 !~ /^2/ { n++ } END { print n + 0 }' "$dir/latency.csv")
			echo "| $kind | $count | $(echo "$seconds" | p95) | $bad |"
		done
		echo
		echo "### Images on arm64"
		echo
		echo "| Service | Image | Arch | State |"
		echo "|---|---|---|---|"
		awk -F, '$1 != "service" { print "| " $1 " | " $2 " | " $3 " | " $4 " |" }' "$dir/images.csv"
		echo
		echo "### Thresholds"
		echo
		thresholds "$dir" | sed 's/^/- /'
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

# Times the UI pages and the API calls the web app makes, once a second.
sample_latency() {
	while :; do
		ts=$(date +%s)
		probe "$ts" ui / "$URL/"
		probe "$ts" ui /projects "$URL/projects"
		probe "$ts" api /org "$API_BASE/org?page=0&entries_per_page=50"
		probe "$ts" api /analyzers "$API_BASE/org/$org/analyzers?page=0&entries_per_page=100"
		probe "$ts" api /analysis "$API_BASE/org/$org/projects/$project_id/analyses/$analysis"
		sleep 1
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
	JOBS="version-check generate-secrets knowledge-restore migrate default-analyzer"
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

	# Pulls what the registry has for this arch; an image without an arm64 variant stays missing and its service is not started.
	compose config --format json >"$work/config.json"
	jq -r '.services | to_entries[] | "\(.key) \(.value.image // "-")"' "$work/config.json" >"$work/services.txt"
	compose pull --ignore-pull-failures >"$out/pull.log" 2>&1 || true
	: >"$work/arch.txt"
	while read -r service image; do
		arch=$(docker image inspect -f '{{.Architecture}}' "$image" 2>/dev/null) || arch=missing
		echo "$service $image $arch" >>"$work/arch.txt"
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
	tar -czf "$work/app.tar.gz" -C "$project" package.json package-lock.json
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
check)
	[ $# -eq 2 ] || usage
	[ -f "$2/timing.env" ] || { echo "check: no $2/timing.env" >&2; exit 1; }
	results=$(thresholds "$2")
	echo "$results"
	! echo "$results" | grep -q '^FAIL'
	;;
*) usage ;;
esac
