#!/usr/bin/env bash
# Dismisses open Dependabot alerts whose manifest lives in a test or benchmark fixture folder,
# across the CodeClarityCE repos that have such folders. Other alerts are never touched.
#
# Usage:
#   scripts/dismiss-fixture-alerts.sh --dry-run   # list what it would dismiss, change nothing
#   scripts/dismiss-fixture-alerts.sh             # dismiss them
#
# Each dismissal uses the reason "tolerable risk" and the comment below. Only open alerts are
# read, so a re-run dismisses nothing new. Prints one count per repo.
#
# Env: FIXTURE_ALERTS_ORG (default CodeClarityCE).

set -euo pipefail

ORG="${FIXTURE_ALERTS_ORG:-CodeClarityCE}"
REASON="tolerable_risk"
COMMENT="test fixture: deliberately vulnerable input"

# The known fixture folders, one "repo folder/" per line. A manifest matches when its path
# starts with the folder, so a root go.mod or pnpm-lock.yaml never does.
FIXTURE_FOLDERS="
plugin-sbom-javascript tests/
plugin-sca-patching tests/
plugin-sbom-php tests/
codeclarity-dev .cloud/scripts/measure/baseline-project/
codeclarity-dev scripts/benchmark/fixtures/
.github fixtures/
"

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# The repos that have fixture folders, in table order.
fixture_repos() {
	awk 'NF && !seen[$1]++ { print $1 }' <<<"$FIXTURE_FOLDERS"
}

# "number<TAB>manifest" of each open alert of <repo> inside one of its fixture folders.
fixture_alerts() {
	local repo="$1" folders
	folders="$(awk -v r="$repo" '$1 == r { print $2 }' <<<"$FIXTURE_FOLDERS" | jq -R . | jq -sc .)"
	gh api --paginate "repos/$ORG/$repo/dependabot/alerts?state=open&per_page=100" |
		jq -r --argjson folders "$folders" '.[]
			| .dependency.manifest_path as $p
			| select(any($folders[]; . as $f | $p | startswith($f)))
			| [.number, $p] | @tsv'
}

dismiss_alert() {
	gh api -X PATCH "repos/$ORG/$1/dependabot/alerts/$2" \
		-f state=dismissed -f dismissed_reason="$REASON" -f dismissed_comment="$COMMENT" >/dev/null
}

main() {
	local dry_run=0 repo number manifest count failed=0 rows
	case "${1:-}" in
	"") ;;
	--dry-run) dry_run=1 ;;
	-h | --help)
		sed -n '2,13p' "$0"
		return 0
		;;
	*) die "unknown argument: $1 (see --help)" ;;
	esac

	while read -r repo; do
		if ! rows="$(fixture_alerts "$repo")"; then
			echo "$repo: could not list Dependabot alerts" >&2
			failed=1
			continue
		fi
		count=0
		while IFS=$'\t' read -r number manifest; do
			[[ -n "$number" ]] || continue
			if ((dry_run)); then
				echo "  would dismiss $repo#$number $manifest"
			else
				dismiss_alert "$repo" "$number"
			fi
			count=$((count + 1))
		done <<<"$rows"
		if ((dry_run)); then
			echo "$repo: $count would be dismissed"
		else
			echo "$repo: $count dismissed"
		fi
	done < <(fixture_repos)
	return "$failed"
}

main "$@"
