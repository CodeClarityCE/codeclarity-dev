#!/bin/sh
# Deletes old knowledge dump tags from Docker Hub. Keeps every dated (YYYY-MM-DD) tag from the
# KEEP_WEEKS weeks up to the newest one, every tag a deployment release's docker-compose.yaml
# pins and the tag the dev Compose file on main pins; other tags are not touched. Deletes
# nothing if any of those pins cannot be read.
#
# Usage: sh .cloud/scripts/prune-knowledge-dump-tags.sh
# Env: DOCKERHUB_USERNAME, DOCKERHUB_TOKEN (a token allowed to delete), GH_TOKEN for gh,
#      KEEP_WEEKS (default 8), IMAGE (default codeclarityce/knowledge-dump),
#      RELEASES_REPO (default CodeClarityCE/deployment), DEV_REPO (default CodeClarityCE/codeclarity-dev).
# Needs gh, curl and jq.
set -eu

KEEP_WEEKS=${KEEP_WEEKS:-8}
IMAGE=${IMAGE:-codeclarityce/knowledge-dump}
RELEASES_REPO=${RELEASES_REPO:-CodeClarityCE/deployment}
DEV_REPO=${DEV_REPO:-CodeClarityCE/codeclarity-dev}
DEV_COMPOSE=.cloud/docker/docker-compose.yaml
HUB=https://hub.docker.com

fail() {
	echo "prune-knowledge-dump-tags: $*" >&2
	exit 1
}

case "$KEEP_WEEKS" in "" | *[!0-9]* | 0) fail "KEEP_WEEKS must be a positive number, not $KEEP_WEEKS" ;; esac
case "$IMAGE" in */*) ;; *) fail "IMAGE must be <namespace>/<repository>, not $IMAGE" ;; esac
: "${DOCKERHUB_USERNAME:?}" "${DOCKERHUB_TOKEN:?}"
namespace=${IMAGE%%/*} repository=${IMAGE#*/}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Tags pinned by any release's Compose file, one per line.
gh api --paginate "repos/$RELEASES_REPO/releases" >"$tmp/releases.json" ||
	fail "cannot list the releases of $RELEASES_REPO, deleting nothing"
jq -r '.[] | .assets[] | select(.name == "docker-compose.yaml") | .id' "$tmp/releases.json" >"$tmp/assets" ||
	fail "cannot read the releases of $RELEASES_REPO, deleting nothing"
: >"$tmp/pinned"
while IFS= read -r asset; do
	gh api -H "Accept: application/octet-stream" "repos/$RELEASES_REPO/releases/assets/$asset" >"$tmp/compose" ||
		fail "cannot download release asset $asset of $RELEASES_REPO, deleting nothing"
	grep -o "$IMAGE:[A-Za-z0-9._-]*" "$tmp/compose" | sed "s|^$IMAGE:||" >>"$tmp/pinned" || true
done <"$tmp/assets"
gh api -H "Accept: application/vnd.github.raw" "repos/$DEV_REPO/contents/$DEV_COMPOSE?ref=main" >"$tmp/compose" ||
	fail "cannot read $DEV_COMPOSE on main of $DEV_REPO, deleting nothing"
grep -o "$IMAGE:[A-Za-z0-9._-]*" "$tmp/compose" | sed "s|^$IMAGE:||" >>"$tmp/pinned" || true

# A bearer token, kept in a header file so it stays out of the process list.
jq -n --arg u "$DOCKERHUB_USERNAME" --arg t "$DOCKERHUB_TOKEN" '{identifier: $u, secret: $t}' |
	curl -fsS -X POST -H "Content-Type: application/json" --data-binary @- "$HUB/v2/auth/token" >"$tmp/auth.json" ||
	fail "cannot log in to Docker Hub"
umask 077
printf 'Authorization: Bearer %s\n' "$(jq -er .access_token "$tmp/auth.json")" >"$tmp/auth.header" ||
	fail "Docker Hub gave no token"

# Every tag of the repository, following the pages.
url="$HUB/v2/namespaces/$namespace/repositories/$repository/tags?page_size=100"
: >"$tmp/tags"
while [ -n "$url" ]; do
	curl -fsS -H "@$tmp/auth.header" "$url" >"$tmp/page.json" || fail "cannot list the tags of $IMAGE"
	jq -er '.results[].name' "$tmp/page.json" >>"$tmp/tags" || fail "unexpected tag list for $IMAGE"
	url=$(jq -r '.next // empty' "$tmp/page.json")
	case "$url" in "" | "$HUB/"*) ;; *) fail "unexpected next page: $url" ;; esac
done

grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' "$tmp/tags" | sort -ru >"$tmp/dated" || true
# Tags dated after this cutoff are kept, so manual builds never push weekly ones out.
newest=$(head -n 1 "$tmp/dated")
cutoff=$(jq -rn --arg d "${newest:-1970-01-01}" --argjson w "$KEEP_WEEKS" \
	'($d + "T00:00:00Z" | fromdate) - $w * 7 * 86400 | strftime("%Y%m%d")') || fail "bad tag date $newest"
status=0
while IFS= read -r tag; do
	if [ "$(echo "$tag" | tr -d -)" -gt "$cutoff" ]; then
		echo "keep $IMAGE:$tag (within $KEEP_WEEKS weeks of $newest)"
	elif grep -qxF "$tag" "$tmp/pinned"; then
		echo "keep $IMAGE:$tag (pinned by a release)"
	elif curl -fsS -X DELETE -H "@$tmp/auth.header" "$HUB/v2/namespaces/$namespace/repositories/$repository/tags/$tag"; then
		echo "deleted $IMAGE:$tag"
	else
		echo "prune-knowledge-dump-tags: cannot delete $IMAGE:$tag" >&2
		status=1
	fi
done <"$tmp/dated"
exit "$status"
