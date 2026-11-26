#!/usr/bin/env bash
# Dismisses the open Scorecard alerts (and one CodeQL rule) we decided not to fix, with one
# written reason per check. Run with --help for usage.

set -euo pipefail

ORG="${SCORECARD_ALERTS_ORG:-CodeClarityCE}"

# The reason map: the single record of these decisions (#260, #290, #369, #391). Each key names a
# match in classify below; the value is "<dismissed reason>|<comment>" (comment under 280 chars).
declare -A DECISION=(
	[own-workflow]="won't fix|ADR 0009: our own reusable workflows in CodeClarityCE/.github move on the v1 tag by design; third-party actions stay pinned by SHA."
	[corepack]="won't fix|corepack is installed at an exact version inside a digest-pinned image; a lockfile just for corepack is upkeep for no gain."
	[broker-socket]="false positive|Not a download: curl posts to the devcontainer broker's local unix socket, and perl only filters the reply, so nothing fetched is run."
	[fixture]="used in tests|Test fixture in the .github repo's fixtures/, which exercises the central workflows and is never built or released."
	[x-crypto]="won't fix|GO-2026-5932 is in indirect golang.org/x/crypto and no code imports x/crypto/openpgp. Bump when x/crypto tags a fix."
	[branch-protection]="won't fix|Single active maintainer: stricter branch protection adds nothing with no second reviewer. Revisit when a second maintainer joins."
	[code-review]="won't fix|Single active maintainer; every change goes through a PR and the ci gate. Revisit when a second maintainer joins."
	[fuzzing]="won't fix|No fuzz targets; parsers are covered by fixture tests."
	[cii]="won't fix|Not pursuing the OpenSSF Best Practices badge."
	[ci-tests]="won't fix|The unchecked PRs predate the move to GitHub Actions; every PR now runs the ci gate."
	[codeql-tls]="won't fix|require means encrypt without verifying, by libpq definition; production uses verify-ca; a startup warning now flags require mode"
)

# The CodeQL rule and the files it is dismissed in, one "repo path" per line.
TLS_RULE="go/disabled-certificate-check"
TLS_FILES="
utility-boilerplates plugin_base.go
utility-amqp-helper main.go
utility-dbhelper helper/Postgres.go
"

usage() {
	cat <<'EOF'
Dismisses the open code-scanning alerts we decided not to fix: Scorecard alerts by check, and
CodeQL's go/disabled-certificate-check in the three files where libpq require mode is intended.
Every other alert is left open. The reasons live in the script's reason map (DECISION).

Usage:
  scripts/dismiss-scorecard-alerts.sh --dry-run   # list what it would dismiss and leave open
  scripts/dismiss-scorecard-alerts.sh             # dismiss them

Only open alerts are read, so a re-run dismisses nothing new. Prints one count per repo.
Run it only after the fixes from #260 have reached main, so it never dismisses an alert a fix
would close.

Env: SCORECARD_ALERTS_ORG (default CodeClarityCE).
EOF
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# Line <n> of <path> in <repo> at <sha>; empty when the file cannot be read.
line_at() {
	gh api -H "Accept: application/vnd.github.raw" "repos/$ORG/$1/contents/$2?ref=$3" 2>/dev/null |
		sed -n "${4}p" || true
}

# The DECISION key for one alert, or nothing to leave it open.
# Args: repo tool rule path line sha advisories (space-separated OSV ids from the message).
classify() {
	local repo="$1" tool="$2" rule="$3" path="$4" line="$5" sha="$6" ids="$7" text
	if [[ "$tool" == CodeQL ]]; then
		[[ "$rule" == "$TLS_RULE" ]] && grep -qxF "$repo $path" <<<"$TLS_FILES" && echo codeql-tls
		return 0
	fi
	case "$rule" in
	PinnedDependenciesID)
		if [[ "$repo" == .github && "$path" == fixtures/* ]]; then
			echo fixture
			return 0
		fi
		text="$(line_at "$repo" "$path" "$sha" "$line")"
		if [[ "$path" == .github/workflows/* && "$text" =~ ^[[:space:]-]*uses:[[:space:]]*[\"\']?CodeClarityCE/\.github/[^[:space:]@]+@v1[\"\']?[[:space:]]*(#.*)?$ ]]; then
			echo own-workflow
		elif [[ "$(basename "$path")" == Dockerfile* && "$text" =~ npm[[:space:]]+(install|i)[[:space:]]+(-g|--global)[[:space:]]+corepack@[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$) ]]; then
			echo corepack
		elif [[ "$repo" == codeclarity-dev && "$path" == .devcontainer/broker-client.sh && "$text" =~ ^curl[[:space:]].*--unix-socket[[:space:]] ]]; then
			echo broker-socket
		fi
		;;
	VulnerabilitiesID) [[ "$ids" == GO-2026-5932 ]] && echo x-crypto ;;
	BranchProtectionID) [[ "$repo" != .github ]] && echo branch-protection ;;
	CodeReviewID) echo code-review ;;
	FuzzingID) echo fuzzing ;;
	CIIBestPracticesID) echo cii ;;
	CITestsID) echo ci-tests ;;
	esac
	return 0
}

# Open alerts of one tool, one per line: repo number tool rule path line sha advisories, split by
# the unit separator (\x1f), since a tab would merge with an empty path when read.
# The CodeQL listing keeps only the one rule we dismiss; the rest are out of scope.
list_alerts() {
	local tool="$1" pages
	pages="$(gh api --paginate "orgs/$ORG/code-scanning/alerts?tool_name=$tool&state=open&per_page=100")" ||
		return 1
	jq -rs --arg tool "$tool" --arg rule "$TLS_RULE" 'add // [] | .[]
		| select($tool != "CodeQL" or .rule.id == $rule)
		| .most_recent_instance as $i
		| ($i.location.path // "") as $p
		| [.repository.name, .number, $tool, .rule.id,
			(if $p | startswith("no file") then "" else $p end), ($i.location.start_line // 0), ($i.commit_sha // ""),
			([($i.message.text // "") | scan("osv\\.dev/([A-Za-z0-9-]+)")[0]] | unique | join(" "))]
		| map(tostring) | join("\u001f")' <<<"$pages"
}

# Prints one repo's count line. Args: repo dry_run dismissed open errors.
report() {
	if (($2)); then
		echo "$1: $3 would be dismissed, $4 left open"
	elif (($5)); then
		echo "$1: $3 dismissed, $4 left open, $5 failed"
	else
		echo "$1: $3 dismissed, $4 left open"
	fi
}

dismiss_alert() {
	gh api -X PATCH "repos/$ORG/$1/code-scanning/alerts/$2" \
		-f state=dismissed -f dismissed_reason="$3" -f dismissed_comment="$4" >/dev/null
}

main() {
	local dry_run=0 rows tool repo number rule path line sha ids key where failed=0
	case "${1:-}" in
	"") ;;
	--dry-run) dry_run=1 ;;
	-h | --help)
		usage
		return 0
		;;
	*) die "unknown argument: $1 (see --help)" ;;
	esac

	rows=""
	for tool in Scorecard CodeQL; do
		local listed
		listed="$(list_alerts "$tool")" || die "could not list $tool alerts in $ORG"
		[[ -n "$listed" ]] && rows+="$listed"$'\n'
	done

	# Rows come sorted by repo, so each repo's count prints after its own alerts.
	local current="" dismissed=0 open=0 errors=0
	while IFS=$'\x1f' read -r repo number tool rule path line sha ids; do
		[[ -n "$repo" ]] || continue
		if [[ "$repo" != "$current" ]]; then
			[[ -n "$current" ]] && report "$current" "$dry_run" "$dismissed" "$open" "$errors"
			current="$repo" dismissed=0 open=0 errors=0
		fi
		where="${path:+ $path:$line}"
		key="$(classify "$repo" "$tool" "$rule" "$path" "$line" "$sha" "$ids")"
		if [[ -z "$key" ]]; then
			((dry_run)) && echo "  left open $repo#$number $rule$where"
			open=$((open + 1))
			continue
		fi
		if ((dry_run)); then
			echo "  would dismiss $repo#$number $rule$where (${DECISION[$key]%%|*})"
		elif ! dismiss_alert "$repo" "$number" "${DECISION[$key]%%|*}" "${DECISION[$key]#*|}"; then
			# Keep going: a dropped request must not stop the other dismissals.
			echo "$repo#$number: dismissal failed" >&2
			errors=$((errors + 1))
			failed=1
			continue
		fi
		dismissed=$((dismissed + 1))
	done < <(sort -t$'\x1f' -k1,1 -k2,2n <<<"$rows")
	[[ -n "$current" ]] && report "$current" "$dry_run" "$dismissed" "$open" "$errors"
	return "$failed"
}

main "$@"
