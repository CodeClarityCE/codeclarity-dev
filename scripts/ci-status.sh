#!/usr/bin/env bash
# CI status of every non-archived CodeClarityCE repo, or a wait on some PRs' ci check.
#
# Usage:
#   scripts/ci-status.sh                          # one table row per repo
#   scripts/ci-status.sh --wait api#12 codeclarity-dev#200
#
# The table shows each repo's submodule path (named as scripts/release-all.sh names it, "." for
# this repo, "-" for a repo that is not a submodule), ci on main and develop, CI_RELEASE, open
# PRs and branches other than main and develop. One GraphQL query reads everything but
# CI_RELEASE, which GraphQL does not expose; those lookups run in parallel.
#
# --wait polls each PR's pull_request ci check until it finishes, prints pass or fail per PR,
# and exits non-zero if any failed or timed out.
#
# Env: CI_STATUS_ORG (default CodeClarityCE), WAIT_TIMEOUT_SECONDS (default 3600),
#      POLL_SECONDS (default 20).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORG="${CI_STATUS_ORG:-CodeClarityCE}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-3600}"
POLL_SECONDS="${POLL_SECONDS:-20}"

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Submodule paths
# ---------------------------------------------------------------------------

# "repo path" for this repo and every submodule in the .gitmodules files checked out under ROOT.
submodule_map() {
	echo "codeclarity-dev ."
	gitmodules_under ""
}

# Reads <prefix>.gitmodules and recurses into each submodule that has its own.
gitmodules_under() {
	local prefix="$1" file="$ROOT/${1}.gitmodules" name path url
	[[ -f "$file" ]] || return 0
	while read -r name path; do
		url="$(git config -f "$file" --get "submodule.$name.url")"
		url="${url%.git}"
		echo "${url##*/} $prefix$path"
		gitmodules_under "$prefix$path/"
	done < <(git config -f "$file" --get-regexp '^submodule\..*\.path$' |
		sed -E 's/^submodule\.(.*)\.path (.*)$/\1 \2/')
}

# ---------------------------------------------------------------------------
# Status table
# ---------------------------------------------------------------------------

# The ci check of a branch's head commit, push run first.
read -r -d '' BRANCH_FIELDS <<'EOF' || true
target { ... on Commit { statusCheckRollup { contexts(first: 100) { nodes {
  ... on CheckRun { name status conclusion checkSuite { workflowRun { event } } }
} } } } }
EOF

read -r -d '' STATUS_QUERY <<EOF || true
query(\$org: String!) {
  organization(login: \$org) {
    repositories(first: 100, isArchived: false, orderBy: { field: NAME, direction: ASC }) {
      pageInfo { hasNextPage }
      nodes {
        name
        main: ref(qualifiedName: "refs/heads/main") { $BRANCH_FIELDS }
        develop: ref(qualifiedName: "refs/heads/develop") { $BRANCH_FIELDS }
        refs(refPrefix: "refs/heads/", first: 100) { nodes { name } }
        pullRequests(states: OPEN, first: 100) { nodes { number } }
      }
    }
  }
}
EOF

# Turns the query result into tab-separated "repo main develop prs branches" rows.
read -r -d '' ROWS_JQ <<'EOF' || true
def ci:
  if . == null then "no-branch"
  else [.target.statusCheckRollup.contexts.nodes[]? | select(.name == "ci")]
    | (map(select(.checkSuite.workflowRun.event == "push")) + .) | first
    | if . == null then "-"
      elif .status != "COMPLETED" then "pending"
      else .conclusion | ascii_downcase end
  end;
.data.organization.repositories.nodes[]
| [ .name, (.main | ci), (.develop | ci),
    ([.pullRequests.nodes[] | "#\(.number)"] | join(" ") | if . == "" then "-" else . end),
    ([.refs.nodes[].name | select(. != "main" and . != "develop")] | join(",") | if . == "" then "-" else . end) ]
| @tsv
EOF

status_table() {
	local result repo path value
	result="$(gh api graphql -f query="$STATUS_QUERY" -F org="$ORG")"
	if [[ "$(jq -r '.data.organization.repositories.pageInfo.hasNextPage' <<<"$result")" == true ]]; then
		echo "warning: more than 100 repos; only the first 100 are shown" >&2
	fi

	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	mkdir "$work/release" "$work/path"
	while read -r repo path; do
		echo "$path" >"$work/path/$repo"
	done < <(submodule_map)

	jq -r "$ROWS_JQ" <<<"$result" >"$work/rows"
	while IFS=$'\t' read -r repo _; do
		{
			value="$(gh api "repos/$ORG/$repo/actions/variables/CI_RELEASE" --jq .value 2>/dev/null)" || value=unset
			echo "$value" >"$work/release/$repo"
		} &
	done <"$work/rows"
	wait

	{
		printf 'PATH\tREPO\tMAIN\tDEVELOP\tCI_RELEASE\tPRS\tBRANCHES\n'
		while IFS=$'\t' read -r repo main develop prs branches; do
			path="-"
			[[ -f "$work/path/$repo" ]] && path="$(cat "$work/path/$repo")"
			printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$path" "$repo" "$main" "$develop" \
				"$(cat "$work/release/$repo")" "$prs" "$branches"
		done <"$work/rows" | sort -t $'\t' -k1,1 -k2,2
	} | align
}

# Pads tab-separated columns to a common width.
align() {
	awk -F '\t' '{ for (i = 1; i <= NF; i++) { cell[NR, i] = $i; if (length($i) > w[i]) w[i] = length($i) } n = NF; rows = NR }
		END { for (r = 1; r <= rows; r++) { line = ""; for (i = 1; i <= n; i++) line = line sprintf(i < n ? "%-" (w[i] + 2) "s" : "%s", cell[r, i]); print line } }'
}

# ---------------------------------------------------------------------------
# Waiting on PRs
# ---------------------------------------------------------------------------

# pass, fail or pending for the pull_request ci check of <repo> PR <n>.
pr_ci() {
	local checks
	checks="$(gh pr checks "$2" -R "$ORG/$1" --json name,bucket,event 2>/dev/null || true)"
	jq -r '[.[]? | select(.name == "ci" and .event == "pull_request")] | first
		| if . == null then "pending"
		  elif .bucket == "pass" then "pass"
		  elif .bucket == "fail" or .bucket == "cancel" then "fail"
		  else "pending" end' <<<"${checks:-[]}"
}

wait_prs() {
	local arg state start=$SECONDS failed=0
	local -a pending=()
	for arg; do
		[[ "$arg" =~ ^[A-Za-z0-9._-]+#[0-9]+$ ]] || die "expected repo#number, got '$arg'"
		pending+=("$arg")
	done
	[[ ${#pending[@]} -gt 0 ]] || die "--wait needs at least one repo#number"

	while :; do
		local -a still=()
		for arg in "${pending[@]}"; do
			state="$(pr_ci "${arg%%#*}" "${arg##*#}")"
			case "$state" in
			pass) echo "$arg pass" ;;
			fail)
				echo "$arg fail"
				failed=1
				;;
			*) still+=("$arg") ;;
			esac
		done
		[[ ${#still[@]} -eq 0 ]] && break
		if ((SECONDS - start >= WAIT_TIMEOUT_SECONDS)); then
			printf '%s timeout\n' "${still[@]}"
			return 1
		fi
		pending=("${still[@]}")
		sleep "$POLL_SECONDS"
	done
	return "$failed"
}

main() {
	case "${1:-}" in
	"") status_table ;;
	--wait)
		shift
		wait_prs "$@"
		;;
	-h | --help) sed -n '2,17p' "$0" ;;
	*) die "unknown argument: $1 (see --help)" ;;
	esac
}

# Sourcing defines the functions only, for scripts/tests/ci-status.bats.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
