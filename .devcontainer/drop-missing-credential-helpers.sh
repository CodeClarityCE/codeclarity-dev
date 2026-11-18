#!/bin/sh
# Removes git credential helpers whose program is not in this container, such as the host's
# /opt/homebrew/bin/gh copied in with its ~/.gitconfig, so pushes print no "not found" errors.
# Runs from postCreateCommand; safe to run again.
set -eu
file="${GIT_CONFIG_GLOBAL:-$HOME/.gitconfig}"
[ -f "$file" ] || exit 0

# Succeeds when git can run the helper: a shell snippet, a program on PATH or a git-credential-<name>.
helper_exists() {
	case "$1" in
	'!'*) cmd=${1#!} ;;
	/*) cmd=$1 ;;
	*) cmd="git-credential-${1%% *}" ;;
	esac
	cmd=${cmd%% *}
	case "$cmd" in
	*'('* | *';'*) return 0 ;; # a shell function such as VS Code's, not a program
	/*) [ -x "$cmd" ] ;;
	git-credential-*) command -v "$cmd" >/dev/null 2>&1 || [ -x "$(git --exec-path)/$cmd" ] ;;
	*) command -v "$cmd" >/dev/null 2>&1 ;;
	esac
}

entries=$(git config --file "$file" --get-regexp '^credential\..*helper$' || true)
printf '%s\n' "$entries" | while read -r key value; do
	[ -n "$key" ] && [ -n "$value" ] || continue
	helper_exists "$value" && continue
	git config --file "$file" --fixed-value --unset-all "$key" "$value"
	echo "removed $key $value (not in this container)"
done

# An empty value only resets the helpers before it; with none left after it, drop it too.
for key in $(git config --file "$file" --name-only --get-regexp '^credential\..*helper$' | sort -u); do
	if [ -z "$(git config --file "$file" --get-all "$key" | tr -d '\n')" ]; then
		git config --file "$file" --unset-all "$key"
	fi
done
