#!/usr/bin/env bash
# Checks or regenerates the root pnpm-lock.yaml for the workspace packages' package.json (api and
# frontend), with the pnpm root package.json pins, in the pinned Node image. Needs only Docker.
# Usage: scripts/root-lockfile.sh check    # fail when pnpm-lock.yaml is out of date; writes nothing
#        scripts/root-lockfile.sh update   # rewrite pnpm-lock.yaml in place
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep in sync with NODE_IMAGE in .github/workflows/ci.yml and the api and frontend toolchain target.
NODE_IMAGE="${NODE_IMAGE:-node:26.10.0-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80}"
# The corepack version of the toolchain target; it checks pnpm against packageManager's sha512.
COREPACK_VERSION=0.36.0

usage() {
	sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# The workspace package directories listed under packages: in pnpm-workspace.yaml.
workspace_packages() {
	sed -n '/^packages:/,/^[^[:space:]-]/s/^[[:space:]]*-[[:space:]]*\(.*\)$/\1/p' "$ROOT/pnpm-workspace.yaml" |
		tr -d "\"'" | tr '\n' ' '
}

# Runs pnpm install --lockfile-only in the Node image. check works on a copy of the manifests and
# mounts the repo read-only; update writes /repo/pnpm-lock.yaml as the calling user.
run_pnpm() {
	local mode="$1" mount=/repo flags=""
	[[ "$mode" == check ]] && mount=/repo:ro flags=--frozen-lockfile
	# shellcheck disable=SC2016 # expanded by the container's sh
	docker run --rm --user "$(id -u):$(id -g)" -v "$ROOT:$mount" -w /repo \
		-e HOME=/tmp -e COREPACK_HOME=/tmp/corepack-home -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 -e CI=true \
		-e MODE="$mode" -e FLAGS="$flags" -e PACKAGES="$(workspace_packages)" -e COREPACK_VERSION="$COREPACK_VERSION" \
		"$NODE_IMAGE" sh -euc '
			npm install --prefix /tmp/corepack --no-audit --no-fund --silent "corepack@$COREPACK_VERSION" >/dev/null
			dir=/repo
			if [ "$MODE" = check ]; then
				dir=/tmp/work
				mkdir -p "$dir"
				for f in package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc; do
					[ ! -f "$f" ] || cp "$f" "$dir/"
				done
				for p in $PACKAGES; do
					mkdir -p "$dir/$p"
					cp "$p/package.json" "$dir/$p/"
				done
			fi
			cd "$dir"
			/tmp/corepack/node_modules/.bin/corepack pnpm install --lockfile-only $FLAGS
		'
}

main() {
	local mode="${1:-}" status=0
	case "$mode" in
	check | update) ;;
	-h | --help)
		usage
		return 0
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
	command -v docker >/dev/null || die "docker is not installed"
	# Global, so the EXIT trap still sees it after main returns.
	out="$(mktemp)"
	trap 'rm -f "$out"' EXIT
	run_pnpm "$mode" 2>&1 | tee "$out" || status=$?
	((status == 0)) && return 0

	if grep -q minimumReleaseAge "$out"; then
		die "pnpm refused a version published less than minimumReleaseAge (pnpm-workspace.yaml) ago. Wait until it is old enough, then run scripts/root-lockfile.sh update again."
	fi
	if [[ "$mode" == check ]]; then
		[[ "${GITHUB_ACTIONS:-}" == true ]] &&
			echo "::error file=pnpm-lock.yaml::The root pnpm-lock.yaml is out of date with the workspace package.json files. Run scripts/root-lockfile.sh update and commit pnpm-lock.yaml."
		die "the root pnpm-lock.yaml is out of date with the workspace package.json files (pnpm names the importer and specifiers above). Run scripts/root-lockfile.sh update and commit pnpm-lock.yaml."
	fi
	die "pnpm could not regenerate the root pnpm-lock.yaml (see above)"
}

main "$@"
