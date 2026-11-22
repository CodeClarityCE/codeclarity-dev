#!/usr/bin/env bash
# Private vulnerability reporting on every non-archived public CodeClarityCE repo.
#
# Usage:
#   scripts/private-reporting.sh --check   # one "repo on|off|unknown" line per repo, change nothing
#   scripts/private-reporting.sh --apply   # turn it on where it is off, then check again
#
# Both modes exit non-zero while any public repo is off or unknown (unknown: the state could not
# be read, usually because gh lacks admin rights on that repo). Private repos are listed as
# "private" and skipped, since GitHub offers private reporting on public repos only. --apply
# skips repos already on, so a re-run changes nothing. Needs org-owner gh auth (scope: repo).
#
# Env: PRIVATE_REPORTING_ORG (default CodeClarityCE).

set -euo pipefail

ORG="${PRIVATE_REPORTING_ORG:-CodeClarityCE}"

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# "name visibility" of each non-archived repo, in the order the API lists them.
org_repos() {
	gh api --paginate "orgs/$ORG/repos?type=all&per_page=100" \
		--jq '.[] | select(.archived | not) | "\(.name) \(.visibility)"'
}

# on, off or unknown for one repo, retrying a failed read once.
reporting_state() {
	local value
	value="$(gh api "repos/$ORG/$1/private-vulnerability-reporting" --jq .enabled 2>/dev/null)" ||
		value="$(gh api "repos/$ORG/$1/private-vulnerability-reporting" --jq .enabled 2>/dev/null)" ||
		value=""
	case "$value" in
	true) echo on ;;
	false) echo off ;;
	*) echo unknown ;;
	esac
}

# Prints each repo's state and exits non-zero if any is not on.
check() {
	local repo visibility state total=0 bad=0
	while read -r repo visibility; do
		if [[ "$visibility" == private ]]; then
			echo "$repo private"
			continue
		fi
		state="$(reporting_state "$repo")"
		echo "$repo $state"
		total=$((total + 1))
		[[ "$state" == on ]] || bad=$((bad + 1))
	done < <(org_repos)
	if ((bad > 0)); then
		echo "$bad of $total public repos have private vulnerability reporting off or unknown"
		return 1
	fi
	echo "all $total public repos have private vulnerability reporting on"
}

# Turns reporting on in each repo where it is off; repos that are on or unknown are left alone.
apply() {
	local repo visibility
	while read -r repo visibility; do
		[[ "$visibility" != private ]] || continue
		[[ "$(reporting_state "$repo")" == off ]] || continue
		if gh api -X PUT "repos/$ORG/$repo/private-vulnerability-reporting" >/dev/null; then
			echo "$repo: turned on"
		else
			echo "$repo: could not turn it on" >&2
		fi
	done < <(org_repos)
}

main() {
	case "${1:-}" in
	--check) check ;;
	--apply)
		apply
		check
		;;
	-h | --help) sed -n '2,14p' "$0" ;;
	*) die "expected --check or --apply (see --help)" ;;
	esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
