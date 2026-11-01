#!/usr/bin/env bash
# Cascading release of every CodeClarityCE repo, in dependency order.
#
# For each repo:
#   1. bump CodeClarityCE go.mod requirements to the tags released upstream in
#      this run (or, for backend / codeclarity-dev, the submodule pointers);
#   2. bump the version file Jenkins checks (config.json, or package.json for
#      api / frontend) to the next vX.Y.(N+1)-alpha;
#   3. open a develop -> main PR with gh, wait for the Jenkins checks, merge it;
#   4. wait for Jenkins' main build to push the image and create the tag +
#      GitHub release (repos without a Jenkins release stage get their release
#      created here instead);
#   5. fast-forward develop onto main.
# The Go dependency graph is derived from each go.mod, so it never drifts.
#
# Usage:
#   scripts/release-all.sh --dry-run            # print order and versions, change nothing
#   scripts/release-all.sh                      # release everything
#   scripts/release-all.sh --only backend/utilities/types
#   scripts/release-all.sh --yes                # don't ask before each release
#
# Before each repo with changes, it shows the new commits and dependency bumps
# and asks y (release) / n (keep current tag) / q (quit).
#
# Resumable: released (and declined) repos are recorded in scripts/.release-state
# and skipped; delete a line there to be asked again. A repo that failed midway
# resumes with the same version: every step is skipped once it is done.
#
# Env: CI_CHECK_PATTERN (regex of PR checks that must pass, default "jenkins"),
#      CI_TIMEOUT_SECONDS, TAG_TIMEOUT_SECONDS (default 3600 each).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="$ROOT/scripts/.release-state"
CI_CHECK_PATTERN="${CI_CHECK_PATTERN:-jenkins}"
CI_TIMEOUT_SECONDS="${CI_TIMEOUT_SECONDS:-3600}"
TAG_TIMEOUT_SECONDS="${TAG_TIMEOUT_SECONDS:-3600}"
POLL_SECONDS=30

# Resolve our own modules straight from GitHub (no proxy.golang.org lag on
# fresh tags); everything else still goes through the proxy and the sumdb.
export GOWORK=off
export GONOPROXY="github.com/CodeClarityCE/*"

DRY_RUN=0
ASSUME_YES=0
ONLY=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	-y | --yes) ASSUME_YES=1 ;;
	--only)
		ONLY="${2:?--only needs a repo path}"
		shift
		;;
	-h | --help)
		sed -n '2,30p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
	shift
done
ONLY="${ONLY%/}"

log() { printf '\033[1;34m[%s]\033[0m %s\n' "$1" "${*:2}" >&2; }
die() {
	printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2
	exit 1
}
in_repo() { git -C "$ROOT/$1" "${@:2}"; }
gh_in() { (cd "$ROOT/$1" && gh "${@:2}"); }

# ---------------------------------------------------------------------------
# Repo discovery
# ---------------------------------------------------------------------------

# Go submodules: the `use` block of backend/go.work, minus the backend itself.
mapfile -t GO_KEYS < <(
	sed -n '/^use (/,/^)/p' "$ROOT/backend/go.work" |
		sed -n 's#^[[:space:]]*\./\(.\+\)$#backend/\1#p'
)
SUPER_KEYS=(backend api frontend deployment .)

declare -A MODULE_OF KEY_OF
for key in "${GO_KEYS[@]}"; do
	mod="$(sed -n 's/^module[[:space:]]\+//p' "$ROOT/$key/go.mod")"
	MODULE_OF[$key]="$mod"
	KEY_OF[$mod]="$key"
done

# CodeClarityCE modules (in our set) that a Go submodule requires, as "mod version".
ccce_requires() {
	grep -oE 'github\.com/CodeClarityCE/[^[:space:]]+[[:space:]]+v[^[:space:]]+' "$ROOT/$1/go.mod" |
		while read -r mod ver; do
			[[ -n "${KEY_OF[$mod]:-}" && "$mod" != "${MODULE_OF[$1]}" ]] && echo "$mod $ver"
		done || true
}

topo_order() {
	for key in "${GO_KEYS[@]}"; do
		echo "$key $key"
		while read -r mod _; do
			[[ -n "$mod" ]] && echo "${KEY_OF[$mod]} $key"
		done < <(ccce_requires "$key")
	done | tsort
}

mapfile -t ORDER < <(topo_order)
ORDER+=("${SUPER_KEYS[@]}")

jenkinsfile() { echo "$ROOT/$1/.cloud/jenkins/Jenkinsfile"; }
has_jenkins() { [[ -f "$(jenkinsfile "$1")" ]]; }
# Jenkins' main build creates the tag + GitHub release itself.
jenkins_releases() { has_jenkins "$1" && grep -q 'gh release create' "$(jenkinsfile "$1")"; }

# The file whose version Jenkins' "PR Version Check" compares against main.
version_file() {
	if [[ -f "$ROOT/$1/config.json" ]]; then
		echo config.json
	elif [[ -f "$ROOT/$1/package.json" ]] && jenkins_releases "$1"; then
		echo package.json
	fi
}

# ---------------------------------------------------------------------------
# Versions and state
# ---------------------------------------------------------------------------

declare -A NEWTAG
if [[ -f "$STATE_FILE" ]]; then
	while IFS='=' read -r key tag; do
		[[ -n "$key" ]] && NEWTAG[$key]="$tag"
	done <"$STATE_FILE"
fi

latest_tag() {
	in_repo "$1" tag --merged origin/main --list 'v*' --sort=-v:refname | head -1
}

bump() {
	[[ "$1" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]] || die "cannot bump version '$1'"
	echo "v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))${BASH_REMATCH[4]}"
}

# Version as written in the repo's version file (package.json has no "v").
file_version() {
	local file
	file="$(version_file "$1")"
	[[ -n "$file" ]] && jq -r .version "$ROOT/$1/$file"
}

set_file_version() {
	local key="$1" tag="$2" file value
	file="$(version_file "$key")"
	[[ -z "$file" ]] && return
	value="$tag"
	[[ "$file" == package.json ]] && value="${tag#v}"
	# Edit in place (first "version" key only) to keep the file's formatting.
	sed -i "0,/\"version\":[[:space:]]*\"[^\"]*\"/s//\"version\": \"$value\"/" "$ROOT/$key/$file"
	[[ "$(jq -r .version "$ROOT/$key/$file")" == "$value" ]] || die "$key: failed to set $file version"
	# Already bumped by an earlier, interrupted run.
	in_repo "$key" diff --quiet -- "$file" && return
	in_repo "$key" commit -q -m "Bump version to $tag" -- "$file"
}

record() {
	NEWTAG[$1]="$2"
	[[ $DRY_RUN -eq 1 ]] && return
	echo "$1=$2" >>"$STATE_FILE"
}

# "mod@tag" for each CodeClarityCE requirement that is behind its released tag.
pending_bumps() {
	while read -r mod ver; do
		[[ -z "$mod" ]] && continue
		local target="${NEWTAG[${KEY_OF[$mod]}]:-}"
		[[ -n "$target" && "$target" != "$ver" ]] && echo "$mod@$target"
	done < <(ccce_requires "$1")
}

submodule_paths() {
	case "$1" in
	backend) printf '%s\n' "${GO_KEYS[@]#backend/}" ;;
	.) echo backend api frontend deployment | tr ' ' '\n' ;;
	esac
}

# Calls "$@" every POLL_SECONDS until it succeeds; the callee dies on hard failure.
wait_until() {
	local timeout="$1" what="$2" waited=0
	shift 2
	until "$@"; do
		((waited >= timeout)) && die "timed out after ${timeout}s waiting for $what"
		log wait "$what (${waited}s)"
		sleep "$POLL_SECONDS"
		waited=$((waited + POLL_SECONDS))
	done
}

# ---------------------------------------------------------------------------
# Release steps
# ---------------------------------------------------------------------------

preflight() {
	local key fail=die
	[[ $DRY_RUN -eq 1 ]] && fail="log warn"
	if [[ $DRY_RUN -eq 0 ]]; then
		command -v gh >/dev/null || die "gh is not installed"
		command -v jq >/dev/null || die "jq is not installed"
		gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"
		[[ $ASSUME_YES -eq 1 ]] || { : </dev/tty; } 2>/dev/null || die "no terminal to ask on; use --yes"
	fi
	for key in "${ORDER[@]}"; do
		[[ -n "$ONLY" && "$key" != "$ONLY" ]] && continue
		[[ "$(in_repo "$key" branch --show-current)" == develop ]] || $fail "$key is not on develop"
		in_repo "$key" diff --quiet --ignore-submodules=all &&
			in_repo "$key" diff --cached --quiet --ignore-submodules=all ||
			$fail "$key has uncommitted changes"
	done
}

sync_develop() {
	in_repo "$1" fetch -q --tags origin
	in_repo "$1" pull -q --ff-only origin develop
}

bump_go_deps() {
	local key="$1" attempt
	local -a bumps
	mapfile -t bumps < <(pending_bumps "$key")
	[[ ${#bumps[@]} -eq 0 ]] && return

	log "$key" "go get ${bumps[*]}"
	for attempt in 1 2 3 4 5; do
		(cd "$ROOT/$key" && go get "${bumps[@]}") && break
		[[ $attempt -eq 5 ]] && die "$key: go get failed"
		log "$key" "go get failed, retrying in 20s (sumdb may not know the new tag yet)"
		sleep 20
	done
	(cd "$ROOT/$key" && go mod tidy && go build ./...) || die "$key: tidy/build failed"

	if ! in_repo "$key" diff --quiet -- go.mod go.sum; then
		in_repo "$key" commit -q -m "Update go dependencies" -- go.mod go.sum
	fi
}

bump_submodules() {
	local key="$1" sub
	while read -r sub; do
		in_repo "$key" add -- "$sub"
	done < <(submodule_paths "$key")
	if ! in_repo "$key" diff --cached --quiet; then
		log "$key" "commit submodule pointers"
		in_repo "$key" commit -q -m "Update submodules"
	fi
}

# Succeeds once every check matching CI_CHECK_PATTERN passed; dies on failure.
ci_passed() {
	local key="$1" pr="$2" checks failed
	checks="$(gh_in "$key" pr checks "$pr" --json name,bucket 2>/dev/null || true)"
	checks="$(jq -c --arg re "$CI_CHECK_PATTERN" '[.[]? | select(.name | test($re; "i"))]' <<<"${checks:-[]}")"
	failed="$(jq -r '[.[] | select(.bucket == "fail" or .bucket == "cancel") | .name] | join(", ")' <<<"$checks")"
	[[ -n "$failed" ]] && die "$key: PR #$pr checks failed: $failed"
	[[ "$(jq 'length' <<<"$checks")" -gt 0 ]] &&
		[[ "$(jq '[.[] | select(.bucket == "pending")] | length' <<<"$checks")" -eq 0 ]]
}

pr_merged() {
	local state
	state="$(gh_in "$1" pr view "$2" --json state -q .state)"
	[[ "$state" == CLOSED ]] && die "$1: PR #$2 was closed"
	[[ "$state" == MERGED ]]
}

tag_on_remote() {
	[[ -n "$(in_repo "$1" ls-remote --tags origin "refs/tags/$2")" ]]
}

merge_pr() {
	local key="$1" tag="$2" pr
	pr="$(gh_in "$key" pr list --base main --head develop --state open --json number -q '.[0].number')"
	if [[ -z "$pr" ]]; then
		pr="$(gh_in "$key" pr create --base main --head develop \
			--title "Release $tag" --body "Release $tag" | grep -oE '[0-9]+$')"
	fi
	log "$key" "PR #$pr opened"

	if has_jenkins "$key"; then
		wait_until "$CI_TIMEOUT_SECONDS" "$key PR #$pr checks /$CI_CHECK_PATTERN/" ci_passed "$key" "$pr"
	fi
	log "$key" "merging PR #$pr"
	gh_in "$key" pr merge "$pr" --merge || gh_in "$key" pr merge "$pr" --merge --auto ||
		die "$key: cannot merge PR #$pr"
	wait_until "$CI_TIMEOUT_SECONDS" "$key PR #$pr to merge" pr_merged "$key" "$pr"
}

publish_tag() {
	local key="$1" tag="$2" prerelease=false
	tag_on_remote "$key" "$tag" && return
	if jenkins_releases "$key"; then
		log "$key" "waiting for Jenkins' main build (if it failed, re-run it in Jenkins)"
		wait_until "$TAG_TIMEOUT_SECONDS" "Jenkins to release $key $tag" tag_on_remote "$key" "$tag"
	else
		[[ "$tag" =~ alpha|beta ]] && prerelease=true
		gh_in "$key" release create "$tag" --target main --title "Release $tag" \
			--generate-notes --prerelease="$prerelease"
	fi
}

# Fast-forward develop onto main (picks up the release merge commit).
finish_develop() {
	in_repo "$1" fetch -q --tags origin
	in_repo "$1" merge-base --is-ancestor origin/main HEAD && return
	in_repo "$1" merge -q --ff-only origin/main
	in_repo "$1" push -q origin develop
}

# Submodule paths of a super-repo whose checked-out commit differs from the pointer.
moved_submodules() {
	local sub
	while read -r sub; do
		in_repo "$1" diff --quiet -- "$sub" || echo "$sub"
	done < <(submodule_paths "$1")
}

# Shows what would be released; returns 0 for yes, 1 for no, exits on quit.
confirm() {
	local key="$1" cur="$2" tag="$3" answer
	shift 3
	[[ $ASSUME_YES -eq 1 ]] && return 0
	{
		printf '\n\033[1m%s: %s -> %s\033[0m\n' "$key" "$cur" "$tag"
		in_repo "$key" log --oneline --no-decorate "$cur..HEAD" | head -20 | sed 's/^/  /'
		[[ $# -gt 0 ]] && printf '  + %s\n' "$@"
	} >&2
	while :; do
		read -r -p "Release $key as $tag? [y/n/q] " answer </dev/tty
		case "$answer" in
		y | Y) return 0 ;;
		n | N) return 1 ;;
		q | Q) exit 0 ;;
		esac
	done
}

release() {
	local key="$1" cur tag
	local -a changes=()

	if [[ -n "${NEWTAG[$key]:-}" ]]; then
		log "$key" "already handled: ${NEWTAG[$key]} (state file)"
		return
	fi

	sync_develop "$key"
	cur="$(latest_tag "$key")"
	if [[ -n "${MODULE_OF[$key]:-}" ]]; then
		mapfile -t changes < <(pending_bumps "$key")
	else
		mapfile -t changes < <(moved_submodules "$key" | sed 's/$/ (submodule moved)/')
	fi

	# Nothing on develop beyond the latest tag. Also covers a run that died after
	# Jenkins tagged but before develop was fast-forwarded: no second version.
	if in_repo "$key" merge-base --is-ancestor HEAD "$cur" && [[ ${#changes[@]} -eq 0 ]]; then
		log "$key" "nothing new since $cur"
		finish_develop "$key"
		record "$key" "$cur"
		return
	fi

	# Same number on a resumed run: the tag doesn't exist until the release finishes.
	tag="$(bump "$cur")"
	if ! confirm "$key" "$cur" "$tag" "${changes[@]}"; then
		log "$key" "skipped, dependents stay on $cur"
		record "$key" "$cur"
		return
	fi

	if [[ -n "${MODULE_OF[$key]:-}" ]]; then bump_go_deps "$key"; else bump_submodules "$key"; fi
	set_file_version "$key" "$tag"
	in_repo "$key" push -q origin develop

	# Skipped when the PR was already merged by an earlier, interrupted run.
	in_repo "$key" merge-base --is-ancestor HEAD origin/main || merge_pr "$key" "$tag"
	publish_tag "$key" "$tag"

	finish_develop "$key"
	record "$key" "$tag"
	log "$key" "released $tag"
}

plan() {
	local key="$1" cur ahead tag reason by="script" note=""
	local -a bumps=()
	in_repo "$key" fetch -q --tags origin
	cur="$(latest_tag "$key")"
	ahead="$(in_repo "$key" rev-list --count "$cur..origin/develop")"
	jenkins_releases "$key" && by="jenkins"

	if [[ -n "${MODULE_OF[$key]:-}" ]]; then
		mapfile -t bumps < <(pending_bumps "$key")
	elif [[ "$key" == backend || "$key" == . ]]; then
		ahead=$((ahead + 1)) # submodule pointers will move
	fi

	local fv
	fv="$(file_version "$key" || true)"
	[[ -n "$fv" && "v${fv#v}" != "$cur" ]] && note="[$(version_file "$key") says $fv] "

	if [[ -n "${NEWTAG[$key]:-}" ]]; then
		tag="${NEWTAG[$key]}"
		reason="done"
	elif ((ahead > 0 || ${#bumps[@]} > 0)); then
		tag="$(bump "$cur")"
		reason="$ahead commits"
	else
		tag="$cur"
		reason="unchanged"
	fi
	NEWTAG[$key]="$tag"
	printf '%-32s %-15s -> %-15s %-12s %-8s %s%s\n' "$key" "$cur" "$tag" "$reason" "$by" "$note" "${bumps[*]#github.com/CodeClarityCE/}"
}

preflight
[[ -n "$ONLY" && ! " ${ORDER[*]} " =~ " $ONLY " ]] && die "unknown repo '$ONLY' (expected one of: ${ORDER[*]})"

for key in "${ORDER[@]}"; do
	[[ -n "$ONLY" && "$key" != "$ONLY" ]] && continue
	if [[ $DRY_RUN -eq 1 ]]; then plan "$key"; else release "$key"; fi
done
