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
       gate.sh record [DIR]
run loads the recorded registry rows into the running stack, analyses the gate's inputs, records the
API's answers in DIR and checks them; check compares a recorded run with expected/; update rewrites
expected/ from a recorded run (a new run when DIR is left out); record rewrites registry/ from the
stack's rows of a recorded run's packages (when DIR is left out, from a new run on live registries).
Env: as scripts/benchmark/benchmark.sh run, plus RESULTS_GATE_PSQL (see README.md).
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
		cut -f1 "$1/run.tsv" | grep -x "$name" >/dev/null || die "$name: not in the recorded run in $1"
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

# Records a benchmark run of the gate's inputs in $out, its report on stderr.
record_run() {
	set --
	for name in $(inputs); do set -- "$@" --input "$name"; done
	sh "$here/../benchmark/benchmark.sh" run "$@" --out "$out" >&2
}

# The dollar quote around JSON in the SQL; the JSON must not hold it.
# shellcheck disable=SC2016 # a literal SQL dollar quote
tag='$gate_registry$'

# Runs the SQL on stdin in the stack's knowledge database, printing one line per row.
knowledge_sql() {
	# shellcheck disable=SC2086 # a command and its arguments
	${RESULTS_GATE_PSQL:-psql -X -q -t -A -v ON_ERROR_STOP=1 -d knowledge}
}

# Prints JSON $1 dollar-quoted for SQL, or fails when it holds the quote.
quoted() {
	case "$1" in *"$tag"*) die "the registry rows hold $tag, which the SQL quotes them with" ;; esac
	printf '%s%s%s' "$tag" "$1" "$tag"
}

# Prints the recorded registry files, one per line.
registry_files() {
	[ -d "$gate/registry" ] || return 0
	find "$gate/registry" -type f -name '*.json' | LC_ALL=C sort
}

# Prints the packages the analyses of recorded run $1 sent the follower, as a JSON array of
# {language, name}: each SBOM entry, with its ecosystem named as the follower's language.
run_packages() {
	for name in $(inputs); do
		for ws in $(workspaces "$name" "$1"); do
			cat "$1/$name.sbom/$(pages_prefix "$ws")"[0-9]*.json
		done
	done | jq -s -c '[.[].data[] | {name, language: ({npm: "javascript", packagist: "php"}[.ecosystem]
		// error("no follower language for ecosystem \(.ecosystem)"))}] | unique'
}

# Loads the recorded registry rows into the stack's knowledge database in place of the stack's rows
# of those packages, dated now so the follower skips them as fresh; sets $loaded to that time.
load_registry() {
	files=$(registry_files)
	[ -n "$files" ] || die "no recorded registry rows in $gate/registry; record them with gate.sh record"
	docs=$(echo "$files" | while IFS= read -r f; do jq -c . "$f"; done | jq -s -c .)
	loaded=$(
		knowledge_sql <<EOF
-- load the recorded registry rows (scripts/results-gate/registry), dated now
BEGIN;
CREATE TEMP TABLE gate_registry ON COMMIT DROP AS
	SELECT value AS doc FROM jsonb_array_elements($(quoted "$docs")::jsonb);
DELETE FROM package p USING gate_registry r WHERE p.name = r.doc->>'name' AND p.language = r.doc->>'language';
WITH loaded AS (
	INSERT INTO package (name, language, description, homepage, latest_version, "time", keywords, source, license, licenses, extra)
	SELECT doc->>'name', doc->>'language', doc->>'description', doc->>'homepage', doc->>'latest_version', now(),
		doc->>'keywords', doc->'source', doc->>'license', doc->'licenses', doc->'extra'
	FROM gate_registry
	RETURNING id, name, language
)
INSERT INTO version (package_id, version, dependencies, dev_dependencies, extra)
	SELECT l.id, v->>'version', v->'dependencies', v->'dev_dependencies', v->'extra'
	FROM loaded l JOIN gate_registry r ON r.doc->>'name' = l.name AND r.doc->>'language' = l.language
	CROSS JOIN jsonb_array_elements(r.doc->'versions') v;
SELECT extract(epoch FROM now());
COMMIT;
EOF
	) || die "could not load the recorded registry rows into the knowledge database"
	case "$loaded" in
	'' | *[!0-9.]*) die "loading the recorded registry rows printed '$loaded', not the time they were loaded" ;;
	esac
	echo "results gate: loaded the recorded registry rows of $(printf '%s\n' "$docs" | jq length) package(s)"
}

# Fails, naming each one, when a package the analyses of run $1 sent the follower has no recorded
# row, or has a row the follower rewrote after load_registry, so it came from a live registry.
untouched() {
	fetched=$(
		knowledge_sql <<EOF
-- fetched: the run's packages whose rows are not the recorded ones loaded at $loaded
SELECT k.language || ' ' || k.name || CASE WHEN p.id IS NULL THEN ' (not recorded)' ELSE ' (fetched from the registry)' END
FROM jsonb_to_recordset($(quoted "$(run_packages "$1")")::jsonb) AS k(language text, name text)
LEFT JOIN package p ON p.name = k.name AND p.language = k.language
WHERE p.id IS NULL OR extract(epoch FROM p."time") <> $loaded
ORDER BY 1;
EOF
	) || die "could not read the run's packages from the knowledge database"
	[ -n "$fetched" ] || return 0
	printf '%s\n' "$fetched" | sed 's/^/  /' >&2
	die "the run used registry data that is not recorded (above); if the fixtures' packages changed, record them with gate.sh record"
}

# Prints the JSON array of {language, name} of the recorded packages and the expected SBOM entries.
known_packages() {
	{
		registry_files | while IFS= read -r f; do jq -c '{name, language}' "$f"; done
		for name in $(inputs); do
			[ -f "$gate/expected/$name/sbom.tsv" ] || continue
			tail -n +2 "$gate/expected/$name/sbom.tsv" | cut -f2,3 | jq -R -c 'split("\t") |
				{name: .[1], language: ({npm: "javascript", packagist: "php"}[.[0]] // .[0])}'
		done
	} | jq -s -c 'unique'
}

# Deletes the stack's rows of the recorded and expected packages, so the follower fetches them anew.
clear_registry() {
	knowledge_sql >/dev/null <<EOF || die "could not clear the packages' rows in the knowledge database"
-- clear the rows of the gate's packages, so the follower fetches them from the registries
DELETE FROM package p USING jsonb_to_recordset($(quoted "$(known_packages)")::jsonb) AS k(language text, name text)
WHERE p.name = k.name AND p.language = k.language;
EOF
}

# Rewrites registry/ from the stack's rows of the packages the analyses of recorded run $1 sent the follower.
export_registry() {
	recorded "$1"
	packages=$(run_packages "$1")
	[ "$packages" != '[]' ] || die "the run in $1 lists no SBOM entries"
	rows=$(
		knowledge_sql <<EOF
-- export the stack's rows of the run's packages, with their versions
SELECT jsonb_build_object('name', p.name, 'language', p.language, 'description', p.description,
	'homepage', p.homepage, 'latest_version', p.latest_version, 'keywords', p.keywords, 'source', p.source,
	'license', p.license, 'licenses', p.licenses, 'extra', p.extra,
	'versions', COALESCE((SELECT jsonb_agg(jsonb_build_object('version', v.version, 'dependencies', v.dependencies,
		'dev_dependencies', v.dev_dependencies, 'extra', v.extra) ORDER BY v.version COLLATE "C")
		FROM version v WHERE v.package_id = p.id), '[]'::jsonb))::text
FROM package p JOIN jsonb_to_recordset($(quoted "$packages")::jsonb) AS k(language text, name text)
	ON p.name = k.name AND p.language = k.language
ORDER BY p.language, p.name;
EOF
	) || die "could not read the packages' rows from the knowledge database"
	missing=$(printf '%s\n' "$rows" | jq -s -c --argjson want "$packages" '$want - [.[] | {name, language}] |
		.[] | "\(.language) \(.name): no row in the knowledge database"' -r)
	[ -z "$missing" ] || die "the follower did not fetch every package of the run:
$missing"
	staging=$(mktemp -d)
	printf '%s\n' "$rows" | while IFS= read -r row; do
		file="$staging/$(printf '%s\n' "$row" | jq -r '"\(.language)/\(.name)"').json"
		case "$file" in *..*) die "unexpected package name in $file" ;; esac
		mkdir -p "$(dirname "$file")"
		printf '%s\n' "$row" | jq -S . >"$file"
	done
	chmod 755 "$staging"
	rm -rf "$gate/registry"
	mv "$staging" "$gate/registry"
	echo "results gate: recorded the registry rows of $(printf '%s\n' "$packages" | jq length) package(s) in registry/"
}

# Analyses the gate's inputs into $out on the recorded registry rows, and fails if any other came in.
hermetic_run() {
	load_registry
	record_run
	untouched "$out"
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
	hermetic_run
	cmd_check "$out"
}

cmd_update() {
	[ $# -le 1 ] || usage
	if [ $# -eq 1 ]; then
		write_expected "$1"
		return
	fi
	out=$(mktemp -d "${TMPDIR:-/tmp}/codeclarity-results-gate.XXXXXX")
	hermetic_run
	write_expected "$out"
}

# Records the registry rows from recorded run $1, or from a new run on live registries.
cmd_record() {
	[ $# -le 1 ] || usage
	if [ $# -eq 1 ]; then
		export_registry "$1"
		return
	fi
	out=$(mktemp -d "${TMPDIR:-/tmp}/codeclarity-results-gate.XXXXXX")
	clear_registry
	record_run
	export_registry "$out"
	cmd_check "$out"
}

[ $# -gt 0 ] || usage
command=$1
shift
case "$command" in
run) cmd_run "$@" ;;
check) cmd_check "$@" ;;
update) cmd_update "$@" ;;
record) cmd_record "$@" ;;
-h | --help) usage 0 ;;
*) usage ;;
esac
