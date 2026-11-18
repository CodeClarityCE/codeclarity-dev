#!/bin/sh
# Tests the shared git hooks: `make hooks` points every repo at .githooks with a relative, local
# path; pre-commit runs a repo's own hook first, then gitleaks on PATH, else the pinned image through
# Docker, else refuses naming both and --no-verify; other hooks run the repo's own. Uses a made-up
# umbrella with nested submodules and stand-ins for gitleaks and docker, then a real scanner if any.
# Usage: sh .cloud/scripts/tests/githooks.test.sh
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../../.." && pwd)
real_path=$PATH

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

# Git with a throwaway global config, so nothing here reads or changes the developer's own.
HOME="$work/home"
GIT_CONFIG_NOSYSTEM=1
export HOME GIT_CONFIG_NOSYSTEM
mkdir -p "$HOME"
git config --global user.name test
git config --global user.email test@example.com
git config --global init.defaultBranch main
git config --global protocol.file.allow always

# Stand-ins: gitleaks logs its arguments and directory, docker answers `info` only when STUB_DOCKER_UP=1.
stubs="$work/stubs"
mkdir -p "$stubs"
cat >"$stubs/gitleaks" <<'EOF'
#!/bin/sh
echo "$(pwd) $*" >>"$STUB_LOG"
exit "${STUB_GITLEAKS_EXIT:-0}"
EOF
cat >"$stubs/docker" <<'EOF'
#!/bin/sh
[ "$1" = info ] && { [ "${STUB_DOCKER_UP:-}" = 1 ]; exit; }
echo "docker $*" >>"$STUB_LOG"
exit "${STUB_DOCKER_RUN_EXIT:-0}"
EOF
chmod +x "$stubs/gitleaks" "$stubs/docker"
STUB_LOG="$work/stub.log"
export STUB_LOG

# The umbrella holds this checkout's .githooks and install script; sub and sub/nested are submodules.
umbrella="$work/umbrella"
mkdir -p "$work/repos"
for r in sub nested; do
	git init -q "$work/repos/$r"
	git -C "$work/repos/$r" commit -q --allow-empty -m init
done
git -C "$work/repos/sub" submodule add -q "$work/repos/nested" nested
git -C "$work/repos/sub" commit -q -m "add nested"
git init -q "$umbrella"
cp -RP "$src/.githooks" "$umbrella/.githooks"
mkdir -p "$umbrella/.cloud/scripts"
cp "$src/.cloud/scripts/install-hooks.sh" "$umbrella/.cloud/scripts/"
git -C "$umbrella" add -A
git -C "$umbrella" commit -q -m init
git -C "$umbrella" submodule add -q "$work/repos/sub" sub
git -C "$umbrella" submodule update -q --init --recursive
git -C "$umbrella" commit -q -m "add sub"
sub="$umbrella/sub"
nested="$sub/nested"

result=ok
sh "$umbrella/.cloud/scripts/install-hooks.sh" >"$work/out" 2>&1 || result=bad
[ "$(git -C "$umbrella" config --local core.hooksPath)" = .githooks ] || result=bad
[ "$(git -C "$sub" config --local core.hooksPath)" = ../.githooks ] || result=bad
[ "$(git -C "$nested" config --local core.hooksPath)" = ../../.githooks ] || result=bad
[ -z "$(git config --global core.hooksPath)" ] || result=bad
check "make hooks sets a relative, local core.hooksPath in the umbrella and every submodule, recursively" $result

# Stages a change in repo $1 and commits it; the commit's exit code is returned.
commit() {
	echo "$(date +%s%N) $2" >>"$1/file.txt"
	git -C "$1" add file.txt
	git -C "$1" commit -q -m change >"$work/out" 2>&1
}

PATH="$stubs:/usr/bin:/bin"
export PATH

: >"$STUB_LOG"
result=ok
before=$(git -C "$nested" rev-parse HEAD)
commit "$nested" normal || result=bad
[ "$(git -C "$nested" rev-parse HEAD)" != "$before" ] || result=bad
grep -qxF "$nested git --pre-commit --staged --redact --no-banner --verbose --config $umbrella/.githooks/gitleaks.toml ." "$STUB_LOG" ||
	result=bad
check "a commit in a nested submodule runs gitleaks on PATH over the staged changes with the shared config" $result

: >"$STUB_LOG"
result=ok
before=$(git -C "$sub" rev-parse HEAD)
STUB_GITLEAKS_EXIT=1 commit "$sub" leak && result=bad
[ "$(git -C "$sub" rev-parse HEAD)" = "$before" ] || result=bad
check "a gitleaks finding refuses the commit" $result
git -C "$sub" reset -q

# No gitleaks: hide the stand-in.
mv "$stubs/gitleaks" "$work/gitleaks.off"
image=$(sed -n 's/^GITLEAKS_IMAGE=//p' "$src/.githooks/gitleaks.env")

: >"$STUB_LOG"
result=ok
STUB_DOCKER_UP=1 commit "$sub" normal || result=bad
grep -q "^docker run --rm -v $sub:$sub .* $image git --pre-commit --staged --redact --no-banner --verbose --config /gitleaks.toml .\$" "$STUB_LOG" ||
	result=bad
check "with no gitleaks on PATH, the hook runs the pinned image through Docker" $result

: >"$STUB_LOG"
result=ok
before=$(git -C "$sub" rev-parse HEAD)
commit "$sub" normal && result=bad
[ "$(git -C "$sub" rev-parse HEAD)" = "$before" ] || result=bad
grep -q "gitleaks" "$work/out" && grep -q "Docker" "$work/out" && grep -q -- "--no-verify" "$work/out" || result=bad
[ ! -s "$STUB_LOG" ] || result=bad
check "with neither, the commit is refused with a message naming gitleaks, Docker and --no-verify" $result

result=ok
git -C "$sub" commit -q --no-verify -m change >"$work/out" 2>&1 || result=bad
check "git commit --no-verify still commits with neither" $result
mv "$work/gitleaks.off" "$stubs/gitleaks"

# A repo's own hooks, as api and frontend have.
mkdir -p "$sub/.githooks"
# shellcheck disable=SC2016 # the hook expands these when it runs
printf '#!/bin/sh\necho "own pre-commit" >>"$STUB_LOG"\nexit "${OWN_EXIT:-0}"\n' >"$sub/.githooks/pre-commit"
# shellcheck disable=SC2016 # the hook expands these when it runs
printf '#!/bin/sh\necho "own pre-push $*: $(cat)" >>"$STUB_LOG"\n' >"$sub/.githooks/pre-push"
chmod +x "$sub/.githooks/pre-commit" "$sub/.githooks/pre-push"

: >"$STUB_LOG"
result=ok
commit "$sub" normal || result=bad
[ "$(head -n 1 "$STUB_LOG")" = "own pre-commit" ] || result=bad
grep -q -- "--pre-commit --staged" "$STUB_LOG" || result=bad
check "the repo's own pre-commit runs first, then the scan" $result

: >"$STUB_LOG"
result=ok
OWN_EXIT=1 commit "$sub" normal && result=bad
grep -q -- "--pre-commit" "$STUB_LOG" && result=bad
check "a failing own pre-commit refuses the commit without scanning" $result
git -C "$sub" reset -q

: >"$STUB_LOG"
result=ok
git init -q --bare "$work/remote.git"
git -C "$sub" push -q "$work/remote.git" HEAD:refs/heads/main >"$work/out" 2>&1 || result=bad
grep -q "^own pre-push $work/remote.git $work/remote.git: HEAD [0-9a-f]* refs/heads/main " "$STUB_LOG" || result=bad
check "the repo's own pre-push still runs, with its arguments and refs on stdin" $result
rm -rf "$sub/.githooks"

result=ok
version=$(sed -n 's/^GITLEAKS_VERSION=//p' "$src/.githooks/gitleaks.env")
case "$image" in *":v$version@sha256:"*) ;; *) result=bad ;; esac
grep -qx "ARG GITLEAKS_VERSION=$version" "$src/.devcontainer/Dockerfile" || result=bad
check "the image tag and the devcontainer install gitleaks $version" $result

# The real scanner, when this machine has one: a binary, or Docker that can run the image.
PATH=$real_path
scanner=
if command -v gitleaks >/dev/null 2>&1; then
	scanner="gitleaks $(gitleaks version)"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker pull -q "$image" >/dev/null 2>&1; then
	scanner="the pinned image"
fi
if [ -z "$scanner" ]; then
	echo "skip the real-scanner checks: no gitleaks on PATH and no usable Docker"
else
	result=ok
	before=$(git -C "$sub" rev-parse HEAD)
	commit "$sub" "token = \"glpat-$(printf 'x%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)\"" && result=bad
	[ "$(git -C "$sub" rev-parse HEAD)" = "$before" ] || result=bad
	grep -q "gitlab-pat-any-entropy" "$work/out" || result=bad
	grep -q "glpat-xxxx" "$work/out" && result=bad
	check "with $scanner, a staged all-x GitLab token is refused, with the value redacted" $result
	git -C "$sub" checkout -q -- file.txt 2>/dev/null || :
	git -C "$sub" reset -q --hard

	result=ok
	commit "$sub" 'token = "glpat-test-token"' || result=bad
	check "with $scanner, a normal change commits" $result
fi

echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
