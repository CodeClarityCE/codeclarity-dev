# shellcheck shell=sh
# Defines compose() and compose_debug(): docker compose with the dev stack's files.
# Source it from .cloud/scripts. The file list is .cloud/docker/compose-files.txt, shared with the broker.
# Env: COMPOSE_ROOT, the repo root (default ../..).

COMPOSE_ROOT=${COMPOSE_ROOT:-../..}

# _compose_run runs docker compose with each listed file, plus its debug overlay when $1 is debug.
_compose_run() {
	_compose_mode=$1
	shift
	_compose_count=$#
	_compose_list="$COMPOSE_ROOT/.cloud/docker/compose-files.txt"
	[ -f "$_compose_list" ] || {
		echo "Error: no compose file list at $_compose_list" >&2
		return 1
	}
	while IFS= read -r _compose_file || [ -n "$_compose_file" ]; do
		case $_compose_file in '' | '#'*) continue ;; esac
		set -- "$@" -f "$COMPOSE_ROOT/$_compose_file"
		_compose_debug="$COMPOSE_ROOT/${_compose_file%.yaml}.debug.yaml"
		if [ "$_compose_mode" = debug ] && [ -f "$_compose_debug" ]; then
			set -- "$@" -f "$_compose_debug"
		fi
	done <"$_compose_list"
	# Move the caller's arguments after the -f options.
	while [ "$_compose_count" -gt 0 ]; do
		set -- "$@" "$1"
		shift
		_compose_count=$((_compose_count - 1))
	done
	docker compose "$@"
}

compose() {
	_compose_run plain "$@"
}

compose_debug() {
	_compose_run debug "$@"
}
