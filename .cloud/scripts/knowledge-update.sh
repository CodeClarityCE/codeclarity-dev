# shellcheck shell=sh
# Runs a knowledge update in the stack's service-package-follower container, so the host needs no Go.
# The devcontainer runs the same commands through the broker (make knowledge-update).
#
# Usage: sh knowledge-update.sh update|update-osv (from .cloud/scripts; the stack must be up)
# Env: NVD_API_KEY for update, else read from SECRETS_FILE (default ../env/.env.secrets).

SECRETS_FILE=${SECRETS_FILE:-../env/.env.secrets}

. ./compose.sh

action=$1
case "$action" in
update-osv) set -- ;;
update)
	if [ -z "${NVD_API_KEY:-}" ] && [ -f "$SECRETS_FILE" ]; then
		NVD_API_KEY=$(sed -n 's/^[[:space:]]*NVD_API_KEY[[:space:]]*=[[:space:]]*//p' "$SECRETS_FILE" | tail -n 1 |
			sed "s/^\"\(.*\)\"\$/\1/; s/^'\(.*\)'\$/\1/")
	fi
	case "${NVD_API_KEY:-}" in "" | '!ChangeMe!')
		echo "Error: set NVD_API_KEY in $SECRETS_FILE (copy .env.secrets.example)" >&2
		exit 1
		;;
	esac
	export NVD_API_KEY
	# -e names the key so its value stays out of argv.
	set -- -e NVD_API_KEY
	;;
*)
	echo "Usage: sh knowledge-update.sh update|update-osv" >&2
	exit 2
	;;
esac

compose exec -T -w /codeclarity/services/knowledge "$@" service-package-follower \
	go run . -knowledge -action "$action"
