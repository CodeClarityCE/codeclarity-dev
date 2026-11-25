#!/usr/bin/env bash
# Puts the pnpm overrides back into a Dependabot npm PR's lockfile, then pushes it.
#
# Usage:
#   scripts/fix-dependabot-lockfile.sh [--dry-run] [--keep] <api|frontend> <pr>
#
# The overrides live in <repo>/.cloud/docker/pnpm-workspace.yaml, which CI and the Dockerfiles
# copy to the root before installing. Dependabot never sees that file, so its lockfiles have no
# overrides block and CI fails with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH. This script clones the
# PR branch into a temp dir, stages the file the same way, regenerates the lockfile without
# running install scripts, checks it, then commits and pushes only pnpm-lock.yaml.
#
# --dry-run prints the lockfile diff stat and does not commit or push.
# --keep leaves the temp clone in place and prints its path.
#
# Env: FIX_LOCKFILE_ORG (default CodeClarityCE),
#      FIX_LOCKFILE_CLONE_BASE (default https://github.com/<org>; the clone URL is <base>/<repo>.git).

set -euo pipefail

ORG="${FIX_LOCKFILE_ORG:-CodeClarityCE}"
CLONE_BASE="${FIX_LOCKFILE_CLONE_BASE:-https://github.com/$ORG}"
COMMIT_MESSAGE="Restore pnpm overrides in lockfile"

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	echo "usage: $0 [--dry-run] [--keep] <api|frontend> <pr>" >&2
	exit 2
}

DRY_RUN=0
KEEP=0
args=()
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=1 ;;
	--keep) KEEP=1 ;;
	-h | --help) usage ;;
	-*) die "unknown option: $arg" ;;
	*) args+=("$arg") ;;
	esac
done
[[ ${#args[@]} -eq 2 ]] || usage
REPO="${args[0]}"
PR="${args[1]}"
case "$REPO" in
api | frontend) ;;
*) die "repo must be api or frontend, got: $REPO" ;;
esac
[[ "$PR" =~ ^[0-9]+$ ]] || die "PR must be a number, got: $PR"

# Only fix open Dependabot PRs whose branch lives in the repo itself.
info="$(gh pr view "$PR" -R "$ORG/$REPO" --json author,headRefName,isCrossRepository,state \
	-q '[.author.login, .headRefName, .isCrossRepository, .state] | @tsv')" ||
	die "could not read $ORG/$REPO#$PR"
IFS=$'\t' read -r author branch cross state <<<"$info"
[[ "$author" == "app/dependabot" ]] || die "$ORG/$REPO#$PR is by $author, not Dependabot"
[[ "$cross" == "false" ]] || die "$ORG/$REPO#$PR comes from a fork"
[[ "$state" == "OPEN" ]] || die "$ORG/$REPO#$PR is $state, not open"

WORK="$(mktemp -d)"
if [[ $KEEP -eq 1 ]]; then
	trap 'echo "clone kept at $WORK/$REPO"' EXIT
else
	trap 'rm -rf "$WORK"' EXIT
fi

echo "Cloning $ORG/$REPO $branch"
git clone -q --depth 1 --branch "$branch" "$CLONE_BASE/$REPO.git" "$WORK/$REPO"
cd "$WORK/$REPO"

[[ -f .cloud/docker/pnpm-workspace.yaml ]] || die "$REPO has no .cloud/docker/pnpm-workspace.yaml"
cp .cloud/docker/pnpm-workspace.yaml pnpm-workspace.yaml

echo "Regenerating pnpm-lock.yaml with the staged overrides"
pnpm install --lockfile-only --ignore-scripts
grep -q '^overrides:' pnpm-lock.yaml || die "the regenerated lockfile has no overrides block"
pnpm install --frozen-lockfile --lockfile-only --ignore-scripts >/dev/null ||
	die "the regenerated lockfile does not pass a frozen install"

changed="$(git status --porcelain)"
if [[ -z "$changed" ]]; then
	echo "pnpm-lock.yaml already matches the overrides; nothing to do"
	exit 0
fi
[[ "$changed" == " M pnpm-lock.yaml" ]] || die "unexpected changes besides pnpm-lock.yaml:"$'\n'"$changed"

git --no-pager diff --stat
if [[ $DRY_RUN -eq 1 ]]; then
	echo "dry run: not committing or pushing"
	exit 0
fi

git add pnpm-lock.yaml
git commit -q -m "$COMMIT_MESSAGE"
git push -q origin "HEAD:refs/heads/$branch"
echo "Pushed the fixed lockfile to $ORG/$REPO#$PR ($branch)"
