#!/bin/sh
# Writes CodeClarity's own SBOM for a release: the CLI analyses the released checkout with the
# Default Analyzer and prints the analysis's SBOM as CycloneDX. Any failed step, or an SBOM that
# misses the api or frontend dependencies, exits non-zero and writes no file.
#
# Usage: sh .cloud/scripts/release-sbom.sh CHECKOUT VERSION OUT
#   CHECKOUT  the released code (the umbrella with its submodules)
#   VERSION   the release tag, such as v0.0.40-alpha
#   OUT       the CycloneDX JSON file to write
# Env: CODECLARITY_URL, CODECLARITY_ORG, CODECLARITY_TOKEN (an analyze Organization token) to use a
#      running instance; without a token, it issues one on the throwaway real stack that
#      `.cloud/scripts/tests/real-stack/stack.sh up` started.
#      CLI (a built codeclarity binary; default: built from backend/ in the pinned Go image).
#      SBOM_REQUIRED (package URL prefixes the SBOM must hold; default: one api and one frontend dependency).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
[ $# -eq 3 ] || {
	echo "usage: release-sbom.sh CHECKOUT VERSION OUT" >&2
	exit 2
}
CHECKOUT=$(cd "$1" && pwd)
VERSION=$2
OUT=$3
SBOM_REQUIRED=${SBOM_REQUIRED:-pkg:npm/%40nestjs/core@ pkg:npm/vue@}
# Keep in sync with real-stack/cli-journey.sh and CodeClarityCE/.github go-checks.yml.
GO_IMAGE=golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The CLI as a release builds it, unless CLI names one.
build_cli() {
	if [ -n "${CLI:-}" ]; then
		echo "$CLI"
		return
	fi
	# Built outside the checkout, so the binary is not part of the analysed code.
	mkdir -p "$WORK/bin"
	cli_version=$(git -C "$root/backend" describe --tags --always 2>/dev/null || echo dev)
	docker run --rm -v "$root/backend:/src:ro" -v "$WORK/bin:/out" -w /src -e GOWORK=off -e GOTOOLCHAIN=local \
		-e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false "$GO_IMAGE" go build -ldflags "-X codeclarity.io/cmd.Version=$cli_version" \
		-o /out/codeclarity . >&2
	echo "$WORK/bin/codeclarity"
}

# Issues an analyze token for the dev account's personal organization on the throwaway stack.
stack_token() {
	API_BASE=https://localhost/api
	CURL_CA="$WORK/ca.crt"
	LOGIN_EMAIL=john.doe@codeclarity.io
	LOGIN_PASSWORD='ThisIs4Str0ngP4ssW0rd?'
	LOGIN_WAIT_SECONDS=60
	# shellcheck source=tests/fresh-install/lib.sh
	. "$here/tests/fresh-install/lib.sh"
	sh "$here/tests/real-stack/stack.sh" ca "$CURL_CA"
	wait_for_login
	[ -n "$token" ] || {
		echo "release-sbom: could not log in to the stack at $API_BASE" >&2
		exit 1
	}
	CODECLARITY_URL=$API_BASE
	CODECLARITY_ORG=$(get '/org?page=0&entries_per_page=50' | jq -er '[.data[] | select(.organization.personal)][0].organization.id')
	expires=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
	CODECLARITY_TOKEN=$(post "/org/$CODECLARITY_ORG/tokens" \
		"{\"name\":\"release-sbom-$VERSION\",\"scope\":\"analyze\",\"expires_on\":\"$expires\"}" | jq -er '.data.secret')
	if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$CODECLARITY_TOKEN"; fi
	SSL_CERT_FILE=$CURL_CA
	export SSL_CERT_FILE
}

[ -n "${CODECLARITY_TOKEN:-}" ] || stack_token
export CODECLARITY_URL CODECLARITY_ORG CODECLARITY_TOKEN
cli_bin=$(build_cli)
export HOME="$WORK/home"
mkdir -p "$HOME"

"$cli_bin" analyze "$CHECKOUT" --name "codeclarity-$VERSION" --analyzer "Default Analyzer" --wait --timeout 45m \
	>"$WORK/analysis.json" || {
	echo "release-sbom: the analysis of $CHECKOUT did not complete" >&2
	exit 1
}
"$cli_bin" results --format cyclonedx --component-name codeclarity --component-version "$VERSION" >"$WORK/sbom.cdx.json" || {
	echo "release-sbom: the CLI could not read the SBOM of the analysis" >&2
	exit 1
}

jq -e '.bomFormat == "CycloneDX" and (.components | length) > 0' "$WORK/sbom.cdx.json" >/dev/null || {
	echo "release-sbom: the SBOM has no components" >&2
	exit 1
}
for prefix in $SBOM_REQUIRED; do
	jq -e --arg p "$prefix" 'any(.components[]; (.purl // "") | startswith($p))' "$WORK/sbom.cdx.json" >/dev/null || {
		echo "release-sbom: the SBOM has no $prefix component, so it misses part of the release" >&2
		exit 1
	}
done

mv "$WORK/sbom.cdx.json" "$OUT"
echo "release-sbom: wrote $OUT ($(jq '.components | length' "$OUT") components)"
