#!/bin/sh
# Tests that the pre-commit hook scans like CI: .githooks/gitleaks.toml has the same rules as
# CodeClarityCE/.github's .gitleaks.toml at REF (default v1), and gitleaks.env the same image as
# its workflow-lint.yml. Skips when that ref has no secret scan yet or GitHub cannot be reached.
# Usage: sh .cloud/scripts/tests/gitleaks-sync.test.sh
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../../.." && pwd)
ref=${REF:-v1}
base="https://raw.githubusercontent.com/CodeClarityCE/.github/$ref"

passed=0 failed=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
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

code=$(curl -sS -o "$work/central.toml" -w '%{http_code}' "$base/.gitleaks.toml" 2>/dev/null) || code=
case "$code" in
200) ;;
404)
	echo "skip: CodeClarityCE/.github at $ref has no .gitleaks.toml yet"
	exit 0
	;;
*)
	echo "skip: could not reach GitHub (HTTP ${code:-none})"
	exit 0
	;;
esac
curl -fsS -o "$work/workflow-lint.yml" "$base/.github/workflows/workflow-lint.yml" || exit 1

# Comment lines may differ: the copy says where it comes from.
result=ok
grep -v '^#' "$work/central.toml" >"$work/central.rules"
grep -v '^#' "$src/.githooks/gitleaks.toml" >"$work/copy.rules"
diff -u "$work/central.rules" "$work/copy.rules" >"$work/out" || result=bad
check ".githooks/gitleaks.toml has the rules of CodeClarityCE/.github's .gitleaks.toml at $ref" $result

result=ok
want=$(sed -n 's/^ *GITLEAKS_IMAGE: *//p' "$work/workflow-lint.yml")
got=$(sed -n 's/^GITLEAKS_IMAGE=//p' "$src/.githooks/gitleaks.env")
echo "workflow-lint.yml: $want, gitleaks.env: $got" >"$work/out"
[ -n "$want" ] && [ "$want" = "$got" ] || result=bad
check ".githooks/gitleaks.env runs the image workflow-lint.yml at $ref pins" $result

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
