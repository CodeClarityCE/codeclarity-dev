#!/bin/sh
# Tests the release SBOM: release-sbom.sh runs the CLI on the released checkout and writes its
# CycloneDX SBOM, and any failed or incomplete run fails without writing one. Uses a stand-in CLI.
# Also checks that the release workflow creates the release only after the SBOM job, with the SBOM.
# Usage: sh .cloud/scripts/tests/release-sbom.test.sh
# shellcheck disable=SC2016 # the greps below look for literal script and workflow text
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
script="$root/.cloud/scripts/release-sbom.sh"
workflow="$root/.github/workflows/release.yml"
passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
VERSION=v0.0.40-alpha

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

# The stand-in CLI logs each call and answers as STUB_CLI says: ok, analyze-fails,
# results-fails, no-components or no-frontend.
cat >"$work/codeclarity" <<'EOF'
#!/bin/sh
echo "$*" >>"$STUB_CLI_LOG"
case "$1" in
analyze)
	[ "$STUB_CLI" = analyze-fails ] && { echo "analysis a-1 failed" >&2; exit 1; }
	echo '{"organization_id":"o-1","project_id":"p-1","analysis_id":"a-1","status":"completed"}'
	;;
results)
	[ "$STUB_CLI" = results-fails ] && { echo "reading the SBOM of analysis a-1: HTTP 404" >&2; exit 1; }
	case "$STUB_CLI" in
	no-components) components='[]' ;;
	no-frontend) components='[{"type":"library","purl":"pkg:npm/%40nestjs/core@11.0.0"}]' ;;
	*) components='[{"type":"library","purl":"pkg:npm/%40nestjs/core@11.0.0"},{"type":"library","purl":"pkg:npm/vue@3.5.0"}]' ;;
	esac
	echo '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"codeclarity","version":"'"$STUB_VERSION"'"}},"components":'"$components"'}'
	;;
*) exit 1 ;;
esac
EOF
chmod +x "$work/codeclarity"
mkdir -p "$work/release"

# Runs the script against a hosted instance (token in the environment) with the stand-in CLI.
sbom() {
	rm -f "$work/sbom.cdx.json"
	: >"$work/cli.log"
	CLI="$work/codeclarity" STUB_CLI=$1 STUB_CLI_LOG="$work/cli.log" STUB_VERSION=$VERSION \
		CODECLARITY_URL=https://cc.example/api CODECLARITY_ORG=o-1 CODECLARITY_TOKEN=ccot_test \
		sh "$script" "$work/release" "$VERSION" "$work/sbom.cdx.json" >"$work/out" 2>&1
}

result=ok
sbom ok || result=bad
jq -e --arg v "$VERSION" '.bomFormat == "CycloneDX" and .metadata.component.version == $v and (.components | length) == 2' \
	"$work/sbom.cdx.json" >/dev/null 2>&1 || result=bad
check "a completed run writes the CycloneDX SBOM of the release" $result

result=ok
grep -qx "analyze $work/release --name codeclarity-$VERSION --analyzer Default Analyzer --wait --timeout 45m" "$work/cli.log" || result=bad
grep -qx "results --format cyclonedx --component-name codeclarity --component-version $VERSION" "$work/cli.log" || result=bad
check "it analyses the released checkout and names the release in the SBOM" $result

for mode in analyze-fails results-fails no-components no-frontend; do
	result=ok
	sbom $mode && result=bad
	[ -e "$work/sbom.cdx.json" ] && result=bad
	check "a run where $mode fails and writes no SBOM" $result
done

result=ok
sbom analyze-fails
grep -q "analysis a-1 failed" "$work/out" || result=bad
check "a failed analysis names the CLI's error" $result

result=ok
CLI="$work/codeclarity" sh "$script" "$work/release" >"$work/out" 2>&1 && result=bad
check "it needs a checkout, a version and an output file" $result

# The release job needs the SBOM job, so a failed SBOM leaves no release and no tag.
result=ok
[ -f "$workflow" ] || result=bad
awk '/^  release:/{r=1} r && /needs:.*sbom/{found=1} END{exit !found}' "$workflow" || result=bad
grep -q 'sh .cloud/scripts/release-sbom.sh ' "$workflow" || result=bad
grep -q 'gh release create "$VERSION" ' "$workflow" || result=bad
grep -q -- '--prerelease="$PRERELEASE" "codeclarity-$VERSION.cdx.json"' "$workflow" || result=bad
check "the release workflow creates the release after the SBOM job, with the SBOM attached" $result

# release-all.sh dispatches the workflow and finds its run by this title.
result=ok
grep -qx 'run-name: Release ${{ inputs.version }}' "$workflow" || result=bad
grep -q 'workflow run release.yml --ref main -f "version=$tag"' "$root/scripts/release-all.sh" || result=bad
grep -q '"Release $tag"' "$root/scripts/release-all.sh" || result=bad
check "release-all.sh dispatches the release workflow and finds its run by its title" $result

echo "release-sbom: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
