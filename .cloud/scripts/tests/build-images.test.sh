#!/bin/sh
# Tests the production CI image build: every default CodeClarity image in the Compose file is built
# from its submodule, profile-only and third-party images are not, and an image no submodule builds,
# a failed build or a version mismatch fails, COMPOSE_OVERRIDE narrows the images, and BUILD_CACHE=gha
# builds through buildx with one GitHub Actions cache scope per image. Uses a stand-in docker and a made-up checkout.
# Usage: sh .cloud/scripts/tests/build-images.test.sh
here=$(cd "$(dirname "$0")" && pwd)
script="$here/fresh-install/build-images.sh"
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_DOCKER_LOG="$work/docker.log"
STUB_COMPOSE_CONFIG="$work/config.json"
STUB_IMAGE_VERSIONS="$work/versions"
SOURCE_DIR="$work/src"
DEPLOYMENT_DIR="$work/src/deployment"
export STUB_DOCKER_LOG STUB_COMPOSE_CONFIG STUB_IMAGE_VERSIONS SOURCE_DIR DEPLOYMENT_DIR

check() {
	if [ "$2" = ok ]; then
		passed=$((passed + 1))
		echo "ok   $1"
	else
		failed=$((failed + 1))
		echo "FAIL $1"
		sed 's/^/     /' "$work/out" 2>/dev/null
	fi
}

# A checkout with api, frontend, one service and one profile-only plugin.
mkdir -p "$SOURCE_DIR/api" "$SOURCE_DIR/frontend" "$SOURCE_DIR/backend/services/packageFollower" \
	"$SOURCE_DIR/backend/plugins/codeql" "$DEPLOYMENT_DIR"
echo '{"name":"api"}' >"$SOURCE_DIR/api/package.json"
echo '{"name":"frontend"}' >"$SOURCE_DIR/frontend/package.json"
echo '{"image_name":"codeclarityce/service-package-follower","version":"v1.2.3"}' \
	>"$SOURCE_DIR/backend/services/packageFollower/config.json"
echo '{"image_name":"codeclarityce/plugin-codeql","version":"v0.1.0"}' >"$SOURCE_DIR/backend/plugins/codeql/config.json"
: >"$DEPLOYMENT_DIR/docker-compose.yaml"

# What `compose config` resolves with no profile: CodeQL is absent.
config() {
	cat >"$STUB_COMPOSE_CONFIG" <<EOF
{"services": {
  "api": {"image": "codeclarityce/api"},
  "migrate": {"image": "codeclarityce/api"},
  "frontend": {"image": "codeclarityce/frontend"},
  "service-follower": {"image": "codeclarityce/service-package-follower"},
  "knowledge-restore": {"image": "codeclarityce/knowledge-dump:2026-11-16"},
  "db": {"image": "postgres:18.6-alpine@sha256:77f5"}$1
}}
EOF
}

# Runs the script with the environment assignments given, if any.
run() {
	: >"$STUB_DOCKER_LOG"
	env "$@" sh "$script" >"$work/out" 2>&1
}

config ""
echo "codeclarityce/service-package-follower v1.2.3" >"$STUB_IMAGE_VERSIONS"
result=ok
run || result=bad
check "builds the default images and exits 0" $result

result=ok
grep -qx "build -q -t codeclarityce/api -f $SOURCE_DIR/api/.cloud/docker/Dockerfile $SOURCE_DIR/api" "$STUB_DOCKER_LOG" || result=bad
grep -qx "build -q -t codeclarityce/frontend -f $SOURCE_DIR/frontend/.cloud/docker/Dockerfile $SOURCE_DIR/frontend" "$STUB_DOCKER_LOG" || result=bad
check "api and frontend build their last stage from their submodules" $result

result=ok
grep -qx "build -q --target plugin --build-arg KIND=services --build-arg PLUGINNAME=packageFollower -t codeclarityce/service-package-follower -f $SOURCE_DIR/backend/services/packageFollower/.cloud/docker/Dockerfile $SOURCE_DIR/backend" "$STUB_DOCKER_LOG" || result=bad
check "a Go service builds its plugin target in the backend workspace" $result

result=ok
[ "$(grep -c '^build ' "$STUB_DOCKER_LOG")" = 3 ] || result=bad
grep -q 'codeql\|knowledge-dump\|postgres' "$STUB_DOCKER_LOG" && result=bad
check "builds each image once and skips profile-only, knowledge dump and third-party images" $result

result=ok
grep -q 'push\|pull' "$STUB_DOCKER_LOG" && result=bad
check "pushes and pulls nothing" $result

config ',
  "service-new": {"image": "codeclarityce/service-new"}'
result=ok
run && result=bad
grep -q 'codeclarityce/service-new: no submodule builds it' "$work/out" || result=bad
check "an image no submodule builds fails, naming it" $result

config ""
result=ok
STUB_BUILD_FAIL=codeclarityce/frontend
export STUB_BUILD_FAIL
run && result=bad
grep -q 'codeclarityce/frontend failed to build from frontend' "$work/out" || result=bad
check "a failed build fails the run, naming the image" $result
unset STUB_BUILD_FAIL

echo "codeclarityce/service-package-follower v1.2.2" >"$STUB_IMAGE_VERSIONS"
result=ok
run && result=bad
grep -q 'runs version v1.2.2, but backend/services/packageFollower/config.json says v1.2.3' "$work/out" || result=bad
check "a built Go image whose config.json version differs from the submodule's fails" $result

echo "codeclarityce/service-package-follower v1.2.3" >"$STUB_IMAGE_VERSIONS"
: >"$work/override.yaml"
result=ok
run COMPOSE_OVERRIDE="$work/override.yaml" || result=bad
grep -qx "compose --project-directory $DEPLOYMENT_DIR -f $DEPLOYMENT_DIR/docker-compose.yaml -f $work/override.yaml config --format json" "$STUB_DOCKER_LOG" || result=bad
check "COMPOSE_OVERRIDE is merged over the deployment file when listing the images" $result

result=ok
run BUILD_CACHE=gha || result=bad
grep -qx "buildx build --load --cache-from type=gha,scope=codeclarityce/api --cache-to type=gha,mode=min,scope=codeclarityce/api -q -t codeclarityce/api -f $SOURCE_DIR/api/.cloud/docker/Dockerfile $SOURCE_DIR/api" "$STUB_DOCKER_LOG" || result=bad
grep -qx "buildx build --load --cache-from type=gha,scope=codeclarityce/service-package-follower --cache-to type=gha,mode=min,scope=codeclarityce/service-package-follower -q --target plugin --build-arg KIND=services --build-arg PLUGINNAME=packageFollower -t codeclarityce/service-package-follower -f $SOURCE_DIR/backend/services/packageFollower/.cloud/docker/Dockerfile $SOURCE_DIR/backend" "$STUB_DOCKER_LOG" || result=bad
grep -q '^build ' "$STUB_DOCKER_LOG" && result=bad
check "BUILD_CACHE=gha builds with buildx, loading each image and caching it in its own scope" $result

result=ok
run BUILD_CACHE=s3 && result=bad
grep -q 'BUILD_CACHE must be empty or gha' "$work/out" || result=bad
check "an unknown BUILD_CACHE fails" $result

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
