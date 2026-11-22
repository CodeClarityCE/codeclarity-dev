#!/usr/bin/env bash
# Checks out a PR's branch in each submodule that has it, and develop in the others, so a change
# spanning repos is tested as one unit (ADR 0020). Nested submodules (backend's) are resolved too.
# Run at the root of a recursive umbrella checkout, before building anything.
# Keeps the pointers on a push (empty <branch>), for develop and main, and when no submodule has it.
# Usage: scripts/same-named-branches.sh <branch>
set -euo pipefail

branch=${1:-}
summary=()

# Prints the submodule paths of repo <dir>, relative to it.
submodule_paths() {
	[ -f "$1/.gitmodules" ] || return 0
	git -C "$1" config -f .gitmodules --get-regexp '^submodule\..*\.path$' | cut -d' ' -f2-
}

# True when <dir>'s origin has branch <name>.
has_branch() {
	[ -n "$(git -C "$1" ls-remote --heads origin "refs/heads/$2")" ]
}

# Checks out origin's <name> at <dir>, detached.
checkout() {
	git -C "$1" fetch -q --depth 1 origin "refs/heads/$2"
	git -C "$1" checkout -q --detach FETCH_HEAD
}

# Resolves every submodule of repo <dir>, then theirs. <prefix> is <dir> relative to the root.
resolve() {
	local dir=$1 prefix=$2 path sub source
	while IFS= read -r path <&3; do
		sub="$dir/$path"
		# A submodule the resolved parent adds is not cloned yet.
		[ -e "$sub/.git" ] || git -C "$dir" submodule update -q --init --depth 1 -- "$path"
		if has_branch "$sub" "$branch"; then
			source="PR branch $branch"
			checkout "$sub" "$branch"
		else
			source="develop (fallback)"
			checkout "$sub" develop
		fi
		summary+=("$prefix$path|$source|$(git -C "$sub" rev-parse --short HEAD)")
		resolve "$sub" "$prefix$path/"
	done 3< <(submodule_paths "$dir")
}

# True when any checked-out submodule, nested ones included, has the branch on its origin.
any_has_branch() {
	local paths path
	# shellcheck disable=SC2016 # foreach expands $displaypath itself.
	paths=$(git submodule --quiet foreach --recursive 'echo "$displaypath"')
	while IFS= read -r path; do
		[ -n "$path" ] && has_branch "$path" "$branch" && return 0
	done <<<"$paths"
	return 1
}

# A push has no PR branch, and develop and main are what the pointers already track.
case $branch in
"" | develop | main)
	echo "Not a same-named-branch PR (branch '${branch}'); keeping the submodule pointers."
	exit 0
	;;
esac
if ! any_has_branch; then
	echo "No submodule has branch $branch; keeping the submodule pointers."
	exit 0
fi
resolve . ""
echo "Submodule checkouts for the same-named-branch PR $branch:"
for row in "${summary[@]}"; do
	IFS='|' read -r path source sha <<<"$row"
	printf '%-40s %-40s %s\n' "$path" "$source" "$sha"
done
