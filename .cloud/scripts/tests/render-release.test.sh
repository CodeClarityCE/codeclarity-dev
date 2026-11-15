#!/bin/sh
# Tests the deployment release render: the released Compose file pins every image by digest,
# carries its config files inline, and an image whose digest cannot be found fails the release.
# Uses a stand-in docker whose registry answers from a digest list.
# Usage: sh .cloud/scripts/tests/render-release.test.sh
# Env: DEPLOYMENT_DIR (default: the deployment submodule).
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
DEPLOYMENT_DIR=$(cd "${DEPLOYMENT_DIR:-$root/deployment}" && pwd)
script="$DEPLOYMENT_DIR/scripts/render-release.sh"
[ -f "$script" ] || { echo "no $script; set DEPLOYMENT_DIR to a deployment checkout" >&2; exit 1; }
chmod +x "$here"/stubs/*
PATH="$here/stubs:$PATH"
export PATH

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
STUB_IMAGE_DIGESTS="$work/registry"
STUB_DOCKER_LOG="$work/docker.log"
export STUB_IMAGE_DIGESTS STUB_DOCKER_LOG
VERSION=v0.0.10-alpha

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

# A made-up digest per image: sha256 of the reference.
digest_of() {
	echo "sha256:$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"
}

# The registry knows every codeclarityce image the deployment Compose file names.
registry_with_every_image() {
	: >"$STUB_IMAGE_DIGESTS"
	for ref in codeclarityce/api codeclarityce/frontend codeclarityce/service-dispatcher \
		codeclarityce/service-downloader codeclarityce/service-package-follower \
		codeclarityce/service-scheduler codeclarityce/service-notifier codeclarityce/service-knowledge \
		codeclarityce/plugin-js-sbom codeclarityce/plugin-license-finder codeclarityce/plugin-vuln-finder \
		codeclarityce/plugin-php-sbom codeclarityce/plugin-codeql codeclarityce/knowledge-dump:2026-11-11; do
		echo "$ref $(digest_of "$ref")" >>"$STUB_IMAGE_DIGESTS"
	done
}

render() {
	sh "$script" "$VERSION" "$1" "$2" >"$work/out" 2>&1
}

# Prints every image reference in a Compose file: image: values and x-*-image anchors, not aliases.
image_refs() {
	sed -n -E 's/^[[:space:]]*(image|x-[a-z-]*image):[[:space:]]*(&[^[:space:]]+[[:space:]]+)?//p' "$1" | grep -v '^\*'
}

test_every_image_in_the_released_compose_file_is_pinned_by_digest() {
	registry_with_every_image
	out="$work/pinned"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	[ -n "$(image_refs "$out/docker-compose.yaml" 2>/dev/null)" ] || result=bad
	image_refs "$out/docker-compose.yaml" 2>/dev/null | grep -Ev '@sha256:[0-9a-f]{64}}?$' >"$work/unpinned" && result=bad
	grep -Eq "^[[:space:]]+image: codeclarityce/api@$(digest_of codeclarityce/api)$" "$out/docker-compose.yaml" 2>/dev/null || result=bad
	[ -s "$work/unpinned" ] && sed 's/^/     unpinned: /' "$work/unpinned" >>"$work/out"
	check "every image in the released Compose file is pinned by digest" $result
}

test_the_knowledge_dump_default_is_pinned_and_stays_overridable() {
	registry_with_every_image
	out="$work/dump"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	want="image: \${KNOWLEDGE_DUMP_IMAGE:-codeclarityce/knowledge-dump:2026-11-11@$(digest_of codeclarityce/knowledge-dump:2026-11-11)}"
	grep -Fq "$want" "$out/docker-compose.yaml" 2>/dev/null || result=bad
	check "the knowledge dump image is pinned by digest and KNOWLEDGE_DUMP_IMAGE still overrides it" $result
}

test_an_image_already_pinned_is_kept_without_a_lookup() {
	registry_with_every_image
	: >"$STUB_DOCKER_LOG"
	out="$work/kept"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	pg="postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873"
	grep -Fq "&postgres-image $pg" "$out/docker-compose.yaml" 2>/dev/null || result=bad
	grep -q postgres "$STUB_DOCKER_LOG" && result=bad
	check "an image already pinned by digest is kept as it is, with no registry lookup" $result
}

# A source directory with a Compose file whose images are given as arguments.
source_with_images() {
	dir="$work/$1"
	shift
	mkdir -p "$dir"
	{
		echo "services:"
		n=0
		for image in "$@"; do
			n=$((n + 1))
			printf '  s%s:\n    image: %s\n' "$n" "$image"
		done
	} >"$dir/docker-compose.yaml"
	cp "$DEPLOYMENT_DIR/.env.example" "$dir/.env.example"
}

test_an_image_the_registry_does_not_know_fails_the_release() {
	registry_with_every_image
	source_with_images unknown codeclarityce/api codeclarityce/plugin-gone:1.0
	out="$work/unknown-out"
	result=ok
	render "$work/unknown" "$out" && result=bad
	grep -q 'codeclarityce/plugin-gone:1.0' "$work/out" || result=bad
	[ -e "$out" ] && result=bad
	check "an image the registry does not know fails the release, names the image and writes nothing" $result
}

test_an_image_set_only_by_a_variable_fails_the_release() {
	registry_with_every_image
	source_with_images variable codeclarityce/api '${API_IMAGE}'
	out="$work/variable-out"
	result=ok
	render "$work/variable" "$out" && result=bad
	grep -q 'API_IMAGE' "$work/out" || result=bad
	[ -e "$out" ] && result=bad
	check "an image set only by a variable cannot be pinned, so it fails the release" $result
}

# Drops trailing blank lines and ends in one newline, as a block scalar's value does.
clip() {
	sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$@" | awk 1
}

# Prints the inline content of a top-level config, with Compose's $$ escapes undone.
config_content() {
	awk -v name="$2" '
	/^[^ ]/ { top = $0 }
	top == "configs:" && $0 == "  " name ":" { want = 1; next }
	want && /^    content: \|2$/ { body = 1; next }
	body && ($0 == "" || /^      /) { print substr($0, 7); next }
	body { exit }
	want && /^  [^ ]/ { exit }
	' "$1" | sed 's/\$\$/$/g' | clip
}

test_every_config_file_is_inlined_with_its_dollar_signs_escaped() {
	registry_with_every_image
	out="$work/inlined"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	awk '/^[^ ]/ { top = $0 } top == "configs:" && /^    file:/' "$out/docker-compose.yaml" 2>/dev/null | grep -q . && result=bad
	files=$(awk '/^[^ ]/ { top = $0 } top == "configs:" && /^  [a-z]/ { n = $1 } top == "configs:" && /^    file:/ { print substr(n, 1, length(n) - 1), $2 }' "$DEPLOYMENT_DIR/docker-compose.yaml")
	[ -n "$files" ] || result=bad
	echo "$files" | while read -r name file; do
		config_content "$out/docker-compose.yaml" "$name" >"$work/content"
		clip "$DEPLOYMENT_DIR/$file" | cmp -s - "$work/content" || {
			echo "     $name differs from $file" >>"$work/out"
			echo bad
		}
	done | grep -q bad && result=bad
	grep -Fq '{$$SERVER_NAME}' "$out/docker-compose.yaml" 2>/dev/null || result=bad
	check "every config file is inlined as content, unchanged once Compose undoes the \$\$ escapes" $result
}

test_a_missing_config_file_fails_the_release() {
	registry_with_every_image
	source_with_images missing codeclarityce/api
	printf 'configs:\n  gone:\n    file: ./config/gone.conf\n' >>"$work/missing/docker-compose.yaml"
	out="$work/missing-out"
	result=ok
	render "$work/missing" "$out" && result=bad
	grep -q 'gone.conf' "$work/out" || result=bad
	[ -e "$out" ] && result=bad
	check "a config file that does not exist fails the release" $result
}

test_the_released_files_name_the_release_version() {
	registry_with_every_image
	out="$work/version"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	grep -qx "CODECLARITY_VERSION=$VERSION" "$out/.env.example" 2>/dev/null || result=bad
	# Every other line of .env.example is shipped as it is.
	grep -v '^CODECLARITY_VERSION=' "$DEPLOYMENT_DIR/.env.example" >"$work/env.src"
	grep -v '^CODECLARITY_VERSION=' "$out/.env.example" 2>/dev/null | cmp -s - "$work/env.src" || result=bad
	grep -qx "x-release-version: &release-version \"$VERSION\"" "$out/docker-compose.yaml" 2>/dev/null || result=bad
	check "the released Compose file and .env.example both name the release version" $result
}

test_the_release_notes_name_the_knowledge_dump_image() {
	registry_with_every_image
	out="$work/notes"
	result=ok
	render "$DEPLOYMENT_DIR" "$out" || result=bad
	want="codeclarityce/knowledge-dump:2026-11-11@$(digest_of codeclarityce/knowledge-dump:2026-11-11)"
	grep -Fq "$want" "$out/release-notes.md" 2>/dev/null || result=bad
	grep -Fq "codeclarityce/api@$(digest_of codeclarityce/api)" "$out/release-notes.md" 2>/dev/null || result=bad
	check "the release notes name the knowledge dump image and every pinned image" $result
}

test_an_empty_config_file_fails_the_release() {
	registry_with_every_image
	source_with_images empty codeclarityce/api
	mkdir -p "$work/empty/config"
	: >"$work/empty/config/empty.conf"
	printf 'configs:\n  empty:\n    file: ./config/empty.conf\n' >>"$work/empty/docker-compose.yaml"
	out="$work/empty-out"
	result=ok
	render "$work/empty" "$out" && result=bad
	grep -q 'empty.conf' "$work/out" || result=bad
	[ -e "$out" ] && result=bad
	check "an empty config file fails the release, since Compose mounts empty content as a path" $result
}

test_every_image_in_the_released_compose_file_is_pinned_by_digest
test_an_empty_config_file_fails_the_release
test_the_released_files_name_the_release_version
test_the_release_notes_name_the_knowledge_dump_image
test_every_config_file_is_inlined_with_its_dollar_signs_escaped
test_a_missing_config_file_fails_the_release
test_the_knowledge_dump_default_is_pinned_and_stays_overridable
test_an_image_already_pinned_is_kept_without_a_lookup
test_an_image_the_registry_does_not_know_fails_the_release
test_an_image_set_only_by_a_variable_fails_the_release

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
