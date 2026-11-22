#!/bin/sh
# Results gate (ADR 0021): analyses the gate's inputs with the accuracy benchmark's runner, then
# compares the findings the API shows with the expected results in expected/. See README.md.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
gate=${RESULTS_GATE_DIR:-$here}
bench=${BENCHMARK_DIR:-$here/../benchmark}
tab=$(printf '\t')

usage() {
	cat >&2 <<'EOF'
usage: gate.sh run [--out DIR]
       gate.sh check DIR
       gate.sh update [DIR]
run analyses the gate's inputs on the running stack, records the API's answers in DIR and checks them;
check compares a recorded run with expected/; update rewrites expected/ from a recorded run (a new run
when DIR is left out). Env: as scripts/benchmark/benchmark.sh run.
EOF
	exit "${1:-2}"
}

die() {
	echo "results gate: $*" >&2
	exit 1
}

# Prints the gate's input names, one per line, without comments.
inputs() {
	grep -v -e '^#' -e '^$' "$gate/inputs.txt"
}

# Prints the result types the gate compares, one per line.
result_types() {
	printf '%s\n' vulnerabilities sbom licences
}

# Prints the header line of result type $1's expected file.
header() {
	case "$1" in
	vulnerabilities) printf 'workspace\tvulnerability\tpackage\tversion\n' ;;
	sbom) printf 'workspace\tecosystem\tpackage\tversion\n' ;;
	licences) printf 'workspace\tlicence\tpackage\tversion\n' ;;
	esac
}

# Prints the workspaces input $1 was read with in recorded run $2, one per line.
workspaces() {
	awk -F '\t' -v name="$1" 'NR > 1 && $1 == name { print ($6 == "" ? "." : $6) }' "$2/run.tsv" | tr ',' '\n'
}

# Prints the folder of recorded run pages that holds result type $1 (see benchmark.sh run_input).
pages_dir() {
	case "$1" in
	vulnerabilities) echo pages ;;
	*) echo "$1" ;;
	esac
}

# Prints the page file prefix of workspace $1: none for ".", else its name and a dash.
pages_prefix() {
	[ "$1" = . ] || printf '%s-' "$1" | tr '/' '_'
}

# Fails unless recorded run $3 holds the first page of result type $1's list for each workspace of input $2.
listed() {
	for ws in $(workspaces "$2" "$3"); do
		[ -f "$3/$2.$(pages_dir "$1")/$(pages_prefix "$ws")0.json" ] ||
			die "$2: no $1 list in the recorded run in $3 (workspace $ws); record a new run"
	done
}

# Prints the normalised results of type $1 for input $2 in recorded run $3: one line per finding,
# without header, in a stable order.
normalise() {
	for ws in $(workspaces "$2" "$3"); do
		prefix=$(pages_prefix "$ws")
		case "$1" in
		vulnerabilities)
			jq -r --arg ws "$ws" '.data[] | .Vulnerability as $v | .Affected[] |
				[$ws, $v, .AffectedDependency, .AffectedVersion] | @tsv' "$3/$2.pages/$prefix"[0-9]*.json
			;;
		sbom)
			jq -r --arg ws "$ws" '.data[] | [$ws, .ecosystem, .name, .version] | @tsv' "$3/$2.sbom/$prefix"[0-9]*.json
			;;
		licences)
			# Each entry is package@version; a scoped package's name holds an @ too.
			jq -r --arg ws "$ws" '.data[] | .id as $l | .deps_using_license[] |
				capture("^(?<p>.+)@(?<v>[^@]*)$") | [$ws, $l, .p, .v] | @tsv' "$3/$2.licences/$prefix"[0-9]*.json
			;;
		esac
	done | LC_ALL=C sort -u
}

# Prints the number of lines in $1, 0 when it is empty.
count() {
	if [ -z "$1" ]; then echo 0; else echo "$1" | wc -l | tr -d ' '; fi
}

# Fails unless $1 holds a recorded run of every gate input on the pinned knowledge dump.
recorded() {
	[ -f "$1/run.tsv" ] || die "no recorded run in $1"
	pin=$(cat "$bench/knowledge-dump.txt")
	got=$(cat "$1/knowledge-dump.txt" 2>/dev/null || :)
	[ "$got" = "$pin" ] || die "the run in $1 used ${got:-an unknown dump} but the gate is pinned to $pin"
	for name in $(inputs); do
		cut -f1 "$1/run.tsv" | grep -qx "$name" || die "$name: not in the recorded run in $1"
	done
}

cmd_check() {
	[ $# -eq 1 ] || usage
	rec=$1
	recorded "$rec"
	diffs=0
	actual=$(mktemp)
	want=$(mktemp)
	trap 'rm -f "$actual" "$want"' EXIT
	for name in $(inputs); do
		for type in $(result_types); do
			file="$gate/expected/$name/$type.tsv"
			[ -f "$file" ] || die "$name: no expected results at $file; write them with gate.sh update $rec"
			listed "$type" "$name" "$rec"
			normalise "$type" "$name" "$rec" >"$actual"
			tail -n +2 "$file" | LC_ALL=C sort -u >"$want"
			appeared=$(LC_ALL=C comm -13 "$want" "$actual")
			disappeared=$(LC_ALL=C comm -23 "$want" "$actual")
			if [ -z "$appeared$disappeared" ]; then
				echo "results gate: $name $type: $(wc -l <"$actual" | tr -d ' ') as expected"
				continue
			fi
			diffs=1
			echo "results gate: $name $type: $(count "$appeared") appeared, $(count "$disappeared") disappeared"
			[ -z "$appeared" ] || echo "$appeared" | sed "s/$tab/  /g; s/^/  appeared:    /"
			[ -z "$disappeared" ] || echo "$disappeared" | sed "s/$tab/  /g; s/^/  disappeared: /"
		done
	done
	if [ "$diffs" -ne 0 ]; then
		echo "results gate: the findings differ from expected/. If the change is intended, run" >&2
		echo "  sh scripts/results-gate/gate.sh update $rec" >&2
		echo "and commit expected/ in the same PR (see scripts/results-gate/README.md)." >&2
		exit 1
	fi
}

# Rewrites expected/ from recorded run $1, keeping the files of other inputs.
write_expected() {
	recorded "$1"
	for name in $(inputs); do
		mkdir -p "$gate/expected/$name"
		for type in $(result_types); do
			listed "$type" "$name" "$1"
			{
				header "$type"
				normalise "$type" "$name" "$1"
			} >"$gate/expected/$name/$type.tsv"
		done
		echo "results gate: wrote expected/$name"
	done
}

# Records a benchmark run of the gate's inputs in $1, its report on stderr.
record_run() {
	set --
	for name in $(inputs); do set -- "$@" --input "$name"; done
	sh "$here/../benchmark/benchmark.sh" run "$@" --out "$out" >&2
}

cmd_run() {
	out=''
	while [ $# -gt 0 ]; do
		case "$1" in
		--out)
			[ $# -ge 2 ] || usage
			out=$2
			shift
			;;
		*) usage ;;
		esac
		shift
	done
	[ -n "$out" ] || out=$(mktemp -d "${TMPDIR:-/tmp}/codeclarity-results-gate.XXXXXX")
	record_run
	cmd_check "$out"
}

cmd_update() {
	[ $# -le 1 ] || usage
	if [ $# -eq 1 ]; then
		write_expected "$1"
		return
	fi
	out=$(mktemp -d "${TMPDIR:-/tmp}/codeclarity-results-gate.XXXXXX")
	record_run
	write_expected "$out"
}

[ $# -gt 0 ] || usage
command=$1
shift
case "$command" in
run) cmd_run "$@" ;;
check) cmd_check "$@" ;;
update) cmd_update "$@" ;;
-h | --help) usage 0 ;;
*) usage ;;
esac
