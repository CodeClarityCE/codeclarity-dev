#!/bin/sh
# Builds every CodeClarity image the deployment Compose file starts by default, from the code the
# submodule pointers name, tagged with the Compose file's own references so `up` never pulls them.
# Go images build inside the backend workspace (go.work), as the dev stack does. Nothing is pushed.
# Usage: sh .cloud/scripts/tests/fresh-install/build-images.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule), SOURCE_DIR (default: this checkout),
#      BUILD_JOBS (parallel builds, default 4).
set -eu

root=$(cd "$(dirname "$0")/../../../.." && pwd)
src=$(cd "${SOURCE_DIR:-$root}" && pwd)
dir=$(cd "${DEPLOYMENT_DIR:-$src/deployment}" && pwd)
BUILD_JOBS=${BUILD_JOBS:-4}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
	echo "build-images: $*" >&2
	exit 1
}

# "<image> <kind> <dir>" for every image this checkout can build; kind is node or go.
for pkg in api frontend; do
	[ -f "$src/$pkg/package.json" ] || continue
	echo "codeclarityce/$(jq -er .name "$src/$pkg/package.json") node $pkg"
done >"$work/sources"
for config in "$src"/backend/services/*/config.json "$src"/backend/plugins/*/config.json; do
	[ -f "$config" ] || continue
	rel=${config#"$src/backend/"}
	echo "$(jq -er .image_name "$config") go ${rel%/config.json}"
done >>"$work/sources"

# The default services' images. Profiles stay off, so profile-only images such as CodeQL are skipped.
# CodeClarity images are untagged in the source Compose file; the knowledge dump keeps its pinned image.
docker compose --project-directory "$dir" -f "$dir/docker-compose.yaml" config --format json >"$work/config.json" ||
	fail "docker compose config failed for $dir/docker-compose.yaml"
jq -r '[.services[].image // empty] | unique[]' "$work/config.json" |
	grep '^codeclarityce/' | grep -v '^codeclarityce/knowledge-dump[:@]' >"$work/images" || true
[ -s "$work/images" ] || fail "no CodeClarity image in $dir/docker-compose.yaml"

: >"$work/plan"
while read -r image; do
	line=$(awk -v ref="${image%:latest}" '$1 == ref' "$work/sources")
	[ -n "$line" ] || fail "$image: no submodule builds it (no package.json name or config.json image_name matches)"
	echo "$image ${line#* }" >>"$work/plan"
done <"$work/images"

# Builds one "<image> <kind> <dir>" line, logging to $work/<n>.log.
build_one() {
	image=$1 kind=$2 path=$3
	log="$work/$(echo "$image" | tr '/:' '__').log"
	case $kind in
	# The last stage, as the node image release builds it.
	node) docker build -q -t "$image" -f "$src/$path/.cloud/docker/Dockerfile" "$src/$path" >"$log" 2>&1 ;;
	# The release's plugin target, with the backend workspace as context.
	go) docker build -q --target plugin --build-arg "KIND=${path%%/*}" --build-arg "PLUGINNAME=${path#*/}" \
		-t "$image" -f "$src/backend/$path/.cloud/docker/Dockerfile" "$src/backend" >"$log" 2>&1 ;;
	esac || {
		echo "::error::build-images: $image failed to build from $path"
		cat "$log"
		return 1
	}
	echo "built $image from $path"
}

status=0
started=0
pids=""
while read -r image kind path; do
	build_one "$image" "$kind" "$path" &
	pids="$pids $!"
	started=$((started + 1))
	if [ $((started % BUILD_JOBS)) -eq 0 ]; then
		for pid in $pids; do wait "$pid" || status=1; done
		pids=""
	fi
done <"$work/plan"
for pid in $pids; do wait "$pid" || status=1; done
[ "$status" -eq 0 ] || fail "some images failed to build"

# A Go image ships its config.json; its version must be the submodule's.
while read -r image kind path; do
	[ "$kind" = go ] || continue
	want=$(jq -er .version "$src/backend/$path/config.json")
	got=$(docker run --rm --entrypoint cat "$image" config.json | jq -er .version) || got=
	[ "$got" = "$want" ] || fail "$image runs version ${got:-unknown}, but backend/$path/config.json says $want"
done <"$work/plan"

echo "build-images: built $(wc -l <"$work/plan" | tr -d ' ') images"
