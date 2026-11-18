#!/bin/sh
# Tests the devcontainer's post-create cleanup of git credential helpers: a helper whose program
# is not in the container is removed, and so is a section's empty reset line once no helper is left
# after it; working helpers, shell functions and other settings stay.
# Usage: sh .cloud/scripts/tests/credential-helpers.test.sh
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../../../.devcontainer/drop-missing-credential-helpers.sh"

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

# A throwaway global config; nothing here reads or changes the developer's own.
HOME="$work/home"
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL="$HOME/.gitconfig"
export HOME GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL
mkdir -p "$HOME" "$work/bin"
printf '#!/bin/sh\n' >"$work/bin/gh"
printf '#!/bin/sh\n' >"$work/bin/git-credential-present"
chmod +x "$work/bin/gh" "$work/bin/git-credential-present"
vscode='!f() { /home/vscode/.vscode-server/bin/x/node /tmp/vscode-remote-containers.js git-credential-helper $*; }; f'

# The host's gh setup-git sections, copied in from macOS, then the VS Code helper.
host_config() {
	rm -f "$GIT_CONFIG_GLOBAL"
	git config --global user.name test
	git config --global --add 'credential.https://github.com.helper' ''
	git config --global --add 'credential.https://github.com.helper' '!/opt/homebrew/bin/gh auth git-credential'
	git config --global --add 'credential.https://gist.github.com.helper' ''
	git config --global --add 'credential.https://gist.github.com.helper' '!/opt/homebrew/bin/gh auth git-credential'
	git config --global credential.helper "$vscode"
}

helpers() {
	git config --global --get-regexp '^credential\..*helper$' 2>/dev/null
}

run() {
	PATH="$work/bin:$PATH" sh "$script" >"$work/out" 2>&1
}

host_config
run
status=$?
result=ok
[ "$status" -eq 0 ] || result=bad
helpers | grep -q homebrew && result=bad
helpers | grep -q 'gist.github.com' && result=bad
[ "$(helpers)" = "credential.helper $vscode" ] || result=bad
[ "$(git config --global user.name)" = test ] || result=bad
grep -q 'removed credential.https://github.com.helper !/opt/homebrew/bin/gh auth git-credential' "$work/out" || result=bad
check "the host's missing gh helper and its reset line go, the VS Code helper stays" "$result"

run
result=ok
[ "$(helpers)" = "credential.helper $vscode" ] || result=bad
[ -s "$work/out" ] && result=bad
check "a second run changes nothing" "$result"

host_config
git config --global --add 'credential.https://github.com.helper' '!gh auth git-credential'
git config --global --add credential.helper present
git config --global --add credential.helper "$work/bin/git-credential-present"
git config --global --add credential.helper osxkeychain
git config --global --add credential.helper "/opt/homebrew/bin/git-credential-manager"
run
result=ok
helpers | grep -q osxkeychain && result=bad
helpers | grep -q git-credential-manager && result=bad
helpers | grep -q homebrew && result=bad
[ "$(git config --global --get-all 'credential.https://github.com.helper' | tr '\n' '|')" = '|!gh auth git-credential|' ] || result=bad
helpers | grep -qx 'credential.helper present' || result=bad
helpers | grep -qx "credential.helper $work/bin/git-credential-present" || result=bad
check "helpers on PATH or by absolute path stay; missing named and absolute ones go" "$result"

rm -f "$GIT_CONFIG_GLOBAL"
run
status=$?
result=ok
[ "$status" -eq 0 ] || result=bad
[ -e "$GIT_CONFIG_GLOBAL" ] && result=bad
check "no global git config is fine" "$result"

echo "passed=$passed failed=$failed"
[ "$failed" -eq 0 ]
