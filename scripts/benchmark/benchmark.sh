#!/bin/sh
# Accuracy benchmark: analyses each pinned input on the running dev stack, records the API's
# answers, and compares every vulnerability instance shown with the committed ground truth.
# See scripts/benchmark/README.md. Never run it in CI.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=${BENCHMARK_ROOT:-$(cd "$here/../.." && pwd)}
dir=${BENCHMARK_DIR:-$here}
API_BASE=${API_URL:-http://localhost:3000}
LOGIN_EMAIL=${LOGIN_EMAIL:-john.doe@codeclarity.io}
LOGIN_PASSWORD=${LOGIN_PASSWORD:-'ThisIs4Str0ngP4ssW0rd?'}
LOGIN_WAIT_SECONDS=${LOGIN_WAIT_SECONDS:-60}
CURL_CA=${CURL_CA:-}
tab=$(printf '\t')

# shellcheck source=../../.cloud/scripts/tests/fresh-install/lib.sh
. "$here/../../.cloud/scripts/tests/fresh-install/lib.sh"

usage() {
	cat >&2 <<'EOF'
usage: benchmark.sh run [--input NAME]... [--out DIR]
       benchmark.sh report DIR
run analyses the inputs (all by default) on the dev stack, records the API's answers in DIR
(a new temporary directory by default) and prints the report; report prints it again from DIR.
Env: API_URL (default http://localhost:3000), LOGIN_EMAIL, LOGIN_PASSWORD, ACTIVE_FILTERS,
     ANALYSIS_WAIT_SECONDS (default 1200).
EOF
	exit "${1:-2}"
}

die() {
	echo "benchmark: $*" >&2
	exit 1
}

# Prints the inputs file's rows (name, repo, commit, subdir, workspaces), without header or comments.
# A fixture row has repo "fixture" and commit "-".
inputs() {
	grep -v -e '^#' -e '^name	' -e '^$' "$dir/inputs.tsv"
}

# Prints the workspaces in list $1 (comma-separated, "." when empty), one per line.
workspace_list() {
	echo "${1:-.}" | tr ',' '\n' | grep -v '^$'
}

# Prints the file name prefix of workspace $1's list pages: none for ".", else the name and a dash.
pages_prefix() {
	[ "$1" = . ] || printf '%s-' "$1" | tr '/' '_'
}

# Prints the knowledge dump image the dev stack restores.
stack_dump() {
	if [ -n "${KNOWLEDGE_DUMP_IMAGE:-}" ]; then
		echo "$KNOWLEDGE_DUMP_IMAGE"
		return
	fi
	sed -n 's/.*\${KNOWLEDGE_DUMP_IMAGE:-\(codeclarityce\/knowledge-dump:[^}]*\)}.*/\1/p' \
		"$root/.cloud/docker/docker-compose.yaml" | head -n 1
}

# Writes input $1's archive (repo $2 at commit $3, subdir $4 as the archive root) to $5. A
# workspace in list $6 that is a submodule there gets the top-level files of its checkout at the
# pinned commit.
# Repo "fixture" archives the committed folder fixtures/$1 as it is in the working tree.
archive_input() {
	if [ "$2" = fixture ]; then
		src="$dir/fixtures/$1"
		[ "$4" = . ] || src="$src/$4"
		[ -d "$src" ] || die "$1: no fixture folder at $src"
		(cd "$src" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | tar -czf "$5" -T -)
		return
	fi
	git -C "$root/$2" cat-file -e "$3^{commit}" 2>/dev/null ||
		die "$1: commit $3 is not in $2; fetch it first (git -C $2 fetch origin $3)"
	tree=$3
	[ "$4" = . ] || tree="$3:$4"
	subs=
	for ws in $(workspace_list "$6"); do
		[ "$ws" = . ] && continue
		sub=$ws
		[ "$4" = . ] || sub="$4/$ws"
		line=$(git -C "$root/$2" ls-tree "$3" -- "$sub")
		case "$line" in "160000 commit "*) ;; *) continue ;; esac
		sha=$(echo "$line" | cut -f1 | cut -d' ' -f3)
		git -C "$root/$2/$sub" cat-file -e "$sha^{commit}" 2>/dev/null ||
			die "$1: submodule $sub commit $sha is not checked out; fetch it first (git -C $2/$sub fetch origin $sha)"
		subs="$subs $ws:$sub:$sha"
	done
	if [ -z "$subs" ]; then
		git -C "$root/$2" archive --format=tar.gz -o "$5" "$tree"
		return
	fi
	staging=$(mktemp -d)
	git -C "$root/$2" archive "$tree" | tar -x -C "$staging"
	for entry in $subs; do
		ws=${entry%%:*} rest=${entry#*:}
		mkdir -p "$staging/$ws"
		# Only its top-level files (manifests and lockfiles), so the upload stays under the API's limit.
		files=$(git -C "$root/$2/${rest%%:*}" ls-tree "${rest#*:}" | awk -F '\t' '$1 ~ / blob / { print $2 }')
		# shellcheck disable=SC2086 # one word per file name
		git -C "$root/$2/${rest%%:*}" archive "${rest#*:}" $files | tar -x -C "$staging/$ws"
	done
	# shellcheck disable=SC2046 # the staged top-level names, which have no spaces
	tar -czf "$5" -C "$staging" $(ls -A "$staging")
	rm -rf "$staging"
}

# Saves every page of analysis $3's list (project $2, org $1) for workspace $5 as
# $4/<prefix><page>.json, the prefix naming the workspace (see pages_prefix).
fetch_pages() {
	mkdir -p "$4"
	n=0
	filters=
	prefix=$(pages_prefix "$5")
	[ -z "${ACTIVE_FILTERS:-}" ] || filters="&active_filters=$ACTIVE_FILTERS"
	while :; do
		get "/org/$1/projects/$2/analysis/$3/vulnerabilities?workspace=$5&entries_per_page=100&page=$n$filters" >"$4/$prefix$n.json" ||
			return 1
		total=$(jq -er '.total_pages' "$4/$prefix$n.json") || return 1
		n=$((n + 1))
		[ "$n" -lt "$total" ] || break
	done
}

# The jq filter that keeps list rows with severity None: no score and no known class.
NONE_ROWS='.data[] | select(((.Severity.Severity // 0) == 0) and ((.Severity.SeverityClass // "NONE") | ascii_upcase | IN("LOW", "MEDIUM", "HIGH", "CRITICAL") | not))'

# Saves the details of each instance the list in $4.pages shows as None (org $1, project $2,
# analysis $3, workspaces in list $5) as $4.none/<n>.json, indexed in $4.none/index.tsv; a
# failed read records null.
fetch_none_details() {
	mkdir -p "$4.none"
	: >"$4.none/index.tsv"
	n=0
	for ws in $(workspace_list "$5"); do
		prefix=$(pages_prefix "$ws")
		jq -r "$NONE_ROWS"' | .Vulnerability as $v | .Affected[] | [$v, .AffectedDependency, .AffectedVersion, ($v | @uri), (.AffectedDependency | @uri), (.AffectedVersion | @uri)] | @tsv' \
			"$4.pages/$prefix"[0-9]*.json | sort -u >"$4.none/rows.tsv"
		while IFS="$tab" read -r id pkg ver uid upkg uver; do
			get "/org/$1/projects/$2/analysis/$3/vulnerabilities/vulnerability/$uid?workspace=$ws&dependency=$upkg&version=$uver" \
				>"$4.none/$n.json" 2>/dev/null || echo '{"data": null}' >"$4.none/$n.json"
			printf '%s\t%s\t%s\t%s\n' "$n" "$id" "$pkg" "$ver" >>"$4.none/index.tsv"
			n=$((n + 1))
		done <"$4.none/rows.tsv"
	done
	rm -f "$4.none/rows.tsv"
}

# Prints, for input $1 in recorded run $2, each instance shown as None whose record has a CVSS
# vector or a GHSA severity, as "N", id, package@version; prints nothing when none were recorded.
none_with_severity() {
	[ -f "$2/$1.none/index.tsv" ] || return 0
	while IFS="$tab" read -r n id pkg ver; do
		if jq -e '.data.severities // {} | (.cvss_4 // .cvss_31 // .cvss_3 // .cvss_2 // .ghsa) != null' \
			"$2/$1.none/$n.json" >/dev/null 2>&1; then
			printf 'N\t%s\t%s\t%s@%s\n' "$1" "$id" "$pkg" "$ver"
		fi
	done <"$2/$1.none/index.tsv" | sort -u
}

# Analyses input $1 (repo $2, commit $3, subdir $4, workspaces $6) in org $5 and records it in $out.
run_input() {
	workspaces=${6:-.}
	archive_input "$1" "$2" "$3" "$4" "$out/$1.tar.gz" "$workspaces"
	short=$(echo "$3" | cut -c1-12)
	[ "$2" != fixture ] || short=fixture
	project=$(post "/org/$5/projects" '{"name":"benchmark-'"$1-$short"'","description":"Accuracy benchmark"}' |
		jq -er '.id') || die "$1: could not create a project"
	upload_archive "$5" "$project" "$out/$1.tar.gz" || die "$1: could not upload the archive"
	analysis=$(start_analysis "$5" "$project") || die "$1: could not start the Default Analyzer"
	echo "benchmark: $1: analysis $analysis started" >&2
	WORK=$out/$1
	mkdir -p "$WORK"
	if ! wait_analysis "$5" "$project" "$analysis"; then
		jq '.data | {status, stage, steps: [.steps[][] | {name: .Name, status: .Status}]}' "$WORK/analysis.json" >&2 2>/dev/null || :
		die "$1: analysis $analysis ended ${status:-without a status}; see make logs SERVICE=plugin-vuln-finder"
	fi
	for ws in $(workspace_list "$workspaces"); do
		fetch_pages "$5" "$project" "$analysis" "$out/$1.pages" "$ws" ||
			die "$1: could not read the vulnerability list of workspace $ws"
	done
	fetch_none_details "$5" "$project" "$analysis" "$out/$1" "$workspaces"
	get "/org/$5/projects/$project/analysis/$analysis/vulnerabilities/knowledge-snapshot" >"$out/$1.knowledge.json" ||
		echo '{"data": null}' >"$out/$1.knowledge.json"
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$analysis" "$workspaces" >>"$out/run.tsv"
}

cmd_run() {
	out= names=
	while [ $# -gt 0 ]; do
		case "$1" in
		--input)
			[ $# -ge 2 ] || usage
			names="$names $2"
			shift
			;;
		--out)
			[ $# -ge 2 ] || usage
			out=$2
			shift
			;;
		*) usage ;;
		esac
		shift
	done
	for n in $names; do
		inputs | cut -f1 | grep -qx "$n" || {
			echo "benchmark: unknown input: $n" >&2
			usage
		}
	done

	pin=$(cat "$dir/knowledge-dump.txt")
	stack=$(stack_dump)
	[ "$stack" = "$pin" ] ||
		die "the dev stack restores ${stack:-an unknown dump} but the benchmark is pinned to $pin; see Refreshing the knowledge in the README"

	[ -n "$out" ] || out=$(mktemp -d "${TMPDIR:-/tmp}/codeclarity-benchmark.XXXXXX")
	mkdir -p "$out"
	printf 'name\trepo\tcommit\tsubdir\tanalysis\tworkspaces\n' >"$out/run.tsv"
	echo "$pin" >"$out/knowledge-dump.txt"

	wait_for_login
	[ -n "$token" ] || die "could not log in to $API_BASE as $LOGIN_EMAIL"
	org=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)][0].organization.id') ||
		die "no personal organization for $LOGIN_EMAIL"

	inputs >"$out/inputs.tsv"
	while IFS="$tab" read -r name repo commit subdir workspaces; do
		if [ -n "$names" ]; then
			case " $names " in *" $name "*) ;; *) continue ;; esac
		fi
		run_input "$name" "$repo" "$commit" "$subdir" "$org" "$workspaces" </dev/null
	done <"$out/inputs.tsv"
	rm -f "$out/inputs.tsv"
	echo "benchmark: recorded in $out" >&2
	cmd_report "$out"
}

# Prints the shown instances of input $1 in recorded run $2 as id, package, version.
shown() {
	jq -r '.data[] | .Vulnerability as $v | .Affected[] | [$v, .AffectedDependency, .AffectedVersion] | @tsv' \
		"$2/$1.pages/"*.json | sort -u
}

# Prints one tagged line per verdict outcome of input $1 in recorded run $2:
# S (counts), W (wrong), M (missed), U (unjudged); fails on a malformed ground truth.
judge() {
	gt="$dir/ground-truth/$1.tsv"
	[ -f "$gt" ] || die "$1: no ground truth at $gt"
	shown "$1" "$2" | awk -F '\t' -v OFS='\t' -v name="$1" -v gt="$gt" '
	BEGIN {
		while ((getline line < gt) > 0) {
			nr++
			if (nr == 1) {
				if (line != "vulnerability\tpackage\tversion\tverdict\tcause\tevidence") { print "bad header in " gt > "/dev/stderr"; bad = 1 }
				continue
			}
			n = split(line, f, "\t")
			key = f[1] SUBSEP f[2] SUBSEP f[3]
			if (n != 6 || f[6] == "") { print gt ": line " nr " needs 6 fields with an evidence link" > "/dev/stderr"; bad = 1 }
			if (key in verdict) { print gt ": " f[1] " " f[2] " " f[3] " is listed twice" > "/dev/stderr"; bad = 1 }
			v = f[4]
			# Graded against the pinned dump: a later withdrawal still counts true, a later record is not expected.
			if (v == "LAG" && f[5] == "withdrawn-after-snapshot") v = "TP"
			else if (v == "LAG" && f[5] == "published-after-snapshot") v = "LATER"
			else if (v != "TP" && v != "FP") { print gt ": " f[1] " has verdict " f[4] " cause " f[5] > "/dev/stderr"; bad = 1 }
			verdict[key] = v
			cause[key] = (f[5] == "-" || f[5] == "") ? "untagged" : f[5]
		}
		if (bad) exit 1
	}
	{
		key = $1 SUBSEP $2 SUBSEP $3
		shownn++
		seen[key] = 1
		if (!(key in verdict) || verdict[key] == "LATER") { unjudged++; print "U", "-", name, $1, $2 "@" $3 }
		else if (verdict[key] == "TP") correct++
		else { wrong++; print "W", cause[key], name, $1, $2 "@" $3 }
	}
	END {
		if (bad) exit 1
		for (key in verdict) {
			if (verdict[key] != "TP") continue
			expected++
			if (key in seen) found++
			else { split(key, k, SUBSEP); print "M", cause[key], name, k[1], k[2] "@" k[3] }
		}
		print "S", name, shownn + 0, correct + 0, wrong + 0, unjudged + 0, expected + 0, found + 0, expected - found
	}'
}

cmd_report() {
	[ $# -eq 1 ] || usage
	rec=$1
	[ -f "$rec/run.tsv" ] || die "no recorded run in $rec"
	lines=$(mktemp)
	none_unrecorded=
	trap 'rm -f "$lines"' EXIT

	echo "Accuracy benchmark"
	echo "Knowledge dump: $(cat "$rec/knowledge-dump.txt" 2>/dev/null || echo unknown)"
	tail -n +2 "$rec/run.tsv" >"$lines.inputs"
	while IFS="$tab" read -r name repo commit subdir analysis workspaces; do
		if [ "$repo" = fixture ]; then
			where="fixture fixtures/$name"
			[ "$subdir" = . ] || where="$where/$subdir"
			echo "$name: $where, analysis $analysis"
		else
			where=$repo
			[ "$subdir" = . ] || where="$repo/$subdir"
			case "${workspaces:-.}" in
			.) echo "$name: $where at $commit, analysis $analysis" ;;
			*) echo "$name: $where at $commit, workspaces $(echo "$workspaces" | sed 's/,/, /g'), analysis $analysis" ;;
			esac
		fi
		echo "  knowledge: $(jq -r '[.data.sources[]? | "\(.source) \(.watermark // "none")"] | if length == 0 then "not recorded" else join(", ") end' \
			"$rec/$name.knowledge.json" 2>/dev/null || echo "not recorded")"
		judge "$name" "$rec" >>"$lines" || exit 1
		none_with_severity "$name" "$rec" >>"$lines"
		[ -f "$rec/$name.none/index.tsv" ] || none_unrecorded=1
	done <"$lines.inputs"
	rm -f "$lines.inputs"

	echo
	awk -F '\t' '
	function pct(a, b) { return b == 0 ? "n/a" : sprintf("%.1f%%", 100 * a / b) }
	function rowf(n, s) {
		split(s, c, " ")
		printf "%-14s %6d %8d %6d %9d %9d %6d %7d %10s %7s\n", n, c[1], c[2], c[3], c[4], c[5], c[6], c[7], pct(c[2], c[2] + c[3]), pct(c[6], c[5])
	}
	$1 == "S" {
		order[++ni] = $2
		stats[$2] = $3 " " $4 " " $5 " " $6 " " $7 " " $8 " " $9
		for (i = 3; i <= 9; i++) tot[i] += $i
	}
	END {
		printf "%-14s %6s %8s %6s %9s %9s %6s %7s %10s %7s\n", "Input", "Shown", "Correct", "Wrong", "Unjudged", "Expected", "Found", "Missed", "Precision", "Recall"
		for (i = 1; i <= ni; i++) rowf(order[i], stats[order[i]])
		rowf("total", tot[3] " " tot[4] " " tot[5] " " tot[6] " " tot[7] " " tot[8] " " tot[9])
	}' "$lines"

	section W "Wrong (shown, but false), by cause:"
	section M "Missed (true, but not shown), by cause:"
	section U "Unjudged (shown, but not in the ground truth):"

	echo
	if [ -n "$none_unrecorded" ]; then
		echo "Severity None with a CVSS vector or GHSA severity: not recorded"
	else
		echo "Severity None with a CVSS vector or GHSA severity: $(grep -c "^N	" "$lines" || :)"
		grep "^N	" "$lines" | sort | awk -F '\t' '{ print "    " $2 "  " $3 "  " $4 }'
	fi
}

# Prints the $lines entries tagged $1 under heading $2, grouped by cause.
section() {
	echo
	echo "$2"
	grep "^$1	" "$lines" | sort -t "$tab" -k2,2 -k3,3 -k4,4 -k5,5 | awk -F '\t' -v tag="$1" '
	{ n[$2]++; item[$2, n[$2]] = $3 "  " $4 "  " $5; if (!($2 in pos)) pos[$2] = ++nc; name[pos[$2]] = $2 }
	END {
		if (nc == 0) print "  none"
		for (i = 1; i <= nc; i++) {
			c = name[i]
			if (tag != "U") print "  " c ": " n[c]
			for (j = 1; j <= n[c]; j++) print "    " item[c, j]
		}
	}'
}

[ $# -gt 0 ] || usage
command=$1
shift
case "$command" in
run) cmd_run "$@" ;;
report) cmd_report "$@" ;;
-h | --help) usage 0 ;;
*) usage ;;
esac
