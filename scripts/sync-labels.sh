#!/usr/bin/env bash
# Keeps the triage and severity labels the same in every non-archived CodeClarityCE repo.
#
# Usage:
#   scripts/sync-labels.sh --check [repo...]   # list labels that are missing or differ, exit 1 if any
#   scripts/sync-labels.sh [repo...]           # create or edit those labels
#
# With no repo names it covers every non-archived repo in the org. Labels it does not manage are
# never touched or deleted, so it is safe to re-run. Apply needs gh auth with write access.
#
# Env: SYNC_LABELS_ORG (default CodeClarityCE).

set -euo pipefail

ORG="${SYNC_LABELS_ORG:-CodeClarityCE}"

# name|color|description. Roles follow docs/agents/triage-labels.md; GitHub caps descriptions at 100 chars.
LABELS=(
	"P1|B60205|Urgent: crash, data loss, security hole or wrong results (a missed or false finding)"
	"P2|D93F0B|Important: a feature is broken or degraded and a workaround exists"
	"P3|FBCA04|Minor: cosmetic or low impact"
	"good first issue|7057FF|Good for newcomers"
	"help wanted|008672|Extra attention is needed"
	"needs-triage|1D76DB|Maintainer needs to evaluate this issue"
	"needs-info|1D76DB|Waiting on reporter for more information"
	"ready-for-agent|D93F0B|Fully specified, ready for an AFK agent"
	"ready-for-human|006B75|Requires human implementation"
	"wontfix|FFFFFF|This will not be worked on"
)

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# The managed labels as the JSON gh label list prints.
managed_labels_json() {
	local entry name color description
	for entry in "${LABELS[@]}"; do
		IFS='|' read -r name color description <<<"$entry"
		jq -n --arg n "$name" --arg c "$color" --arg d "$description" '{name: $n, color: $c, description: $d}'
	done | jq -s .
}

# Prints "missing <name>" or "differs <name>" for each managed label the repo lacks or has changed.
# Names and colors compare case-insensitively, as GitHub treats them.
label_drift() {
	local current
	current="$(gh label list -R "$ORG/$1" --limit 500 --json name,color,description)" || return 1
	jq -r --argjson want "$(managed_labels_json)" '
		map({key: (.name | ascii_downcase), value: .}) | from_entries as $have
		| $want[]
		| ($have[.name | ascii_downcase]) as $h
		| if $h == null then "missing\t\(.name)"
		  elif ($h.color | ascii_downcase) != (.color | ascii_downcase) or ($h.description // "") != .description
		  then "differs\t\(.name)"
		  else empty end' <<<"$current"
}

# Color and description of a managed label.
label_field() {
	local entry name color description
	for entry in "${LABELS[@]}"; do
		IFS='|' read -r name color description <<<"$entry"
		if [[ "$name" == "$1" ]]; then
			if [[ "$2" == color ]]; then echo "$color"; else echo "$description"; fi
			return
		fi
	done
}

all_repos() {
	gh repo list "$ORG" --no-archived --limit 500 --json name --jq '.[].name'
}

main() {
	local check=false repo state name drift=0
	if [[ "${1:-}" == --check ]]; then
		check=true
		shift
	fi
	[[ "${1:-}" != -* ]] || die "unknown option $1"

	local repos=("$@")
	if [[ ${#repos[@]} -eq 0 ]]; then
		mapfile -t repos < <(all_repos)
		[[ ${#repos[@]} -gt 0 ]] || die "no repos found in $ORG"
	fi

	local found
	for repo in "${repos[@]}"; do
		found="$(label_drift "$repo")" || die "could not read the labels of $ORG/$repo"
		while IFS=$'\t' read -r state name; do
			[[ -n "$state" ]] || continue
			if $check; then
				echo "$repo: $state $name"
				drift=1
			else
				gh label create "$name" -R "$ORG/$repo" --force \
					--color "$(label_field "$name" color)" --description "$(label_field "$name" description)" >/dev/null
				if [[ "$state" == missing ]]; then echo "$repo: created $name"; else echo "$repo: updated $name"; fi
			fi
		done <<<"$found"
	done

	if $check; then
		[[ $drift -eq 0 ]] || return 1
		echo "labels in sync"
	fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
