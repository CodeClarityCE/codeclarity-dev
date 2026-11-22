#!/usr/bin/env bash
# Monkey runs: seeded random-interaction Playwright runs on the golden-journey pages of a running
# instance (frontend/e2e/real-stack/monkey.journey.mts), and the ci-failure issue of the nightly
# run. See README.md.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
E2E_REAL_STACK=${E2E_REAL_STACK:-$here/../../frontend/.cloud/scripts/e2e-real-stack.sh}
TITLE="Monkey runs failing"
MARKER="<!-- monkey -->"

usage() {
	cat >&2 <<'EOF'
usage: monkey.sh run URL DIR [PLAYWRIGHT_OPTIONS...]
       monkey.sh issue-body DIR
       monkey.sh report DIR
run runs the @monkey journeys against URL with MONKEY_SEED (a new one when unset) and records
the run in DIR; issue-body prints the ci-failure issue text for a recorded run; report opens,
comments on or closes that issue with gh. Env: MONKEY_SEED, MONKEY_STEPS, RUN_URL.
EOF
	exit "${1:-2}"
}

cmd_run() {
	local url=${1:-} out=${2:-} status
	[[ -n "$url" && -n "$out" ]] || usage
	shift 2
	mkdir -p "$out"
	out=$(cd "$out" && pwd)
	MONKEY_SEED=${MONKEY_SEED:-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')}
	# Checked before any arithmetic, which would run commands hidden in the value.
	[[ "$MONKEY_SEED" =~ ^[0-9]{1,18}$ ]] || {
		echo "monkey: MONKEY_SEED must be a number, got '$MONKEY_SEED'" >&2
		exit 2
	}
	MONKEY_SEED=$((10#$MONKEY_SEED % 2147483648))
	export MONKEY_SEED MONKEY_STEPS
	echo "$MONKEY_SEED" >"$out/seed"
	echo "monkey: seed $MONKEY_SEED against $url (replay with MONKEY_SEED=$MONKEY_SEED)"
	set +e
	sh "$E2E_REAL_STACK" "$url" "$out" --grep @monkey "$@"
	status=$?
	set -e
	echo "$status" >"$out/exit-code"
	return "$status"
}

cmd_issue_body() {
	local dir=${1:-} seed limit=50000 details reports failed
	[[ -n "$dir" ]] || usage
	echo "$MARKER"
	echo
	if [[ ! -f "$dir/exit-code" ]]; then
		echo "The nightly monkey run failed: the monkey did not run, so the stack or the golden journeys before it failed. See ${RUN_URL:-the run logs}."
		return
	fi
	seed=$(cat "$dir/seed" 2>/dev/null || echo unknown)
	reports=$(find "$dir/test-results" -name monkey.md 2>/dev/null | sort)
	failed=$(find "$dir/test-results" -mindepth 1 -maxdepth 1 -type d -name '*monkey*' 2>/dev/null | sort)
	echo "The nightly monkey run with seed $seed found an uncaught error, an error report or a 5xx on a golden-journey page, or could not open one (${RUN_URL:-run link not set})."
	echo
	echo "Each page below gives the command that replays it on a running stack, then what the run saw and the actions it took. The Playwright trace of each failed page is in the run's artifact, \`monkey\`: open it with \`npx playwright show-trace <dir>/trace.zip\`."
	echo
	echo "Once fixed, add the page and seed to \`MONKEY_REGRESSIONS\` in \`frontend/e2e/real-stack/monkey.journey.mts\`, so every run replays it."
	echo
	details=$({
		local test_dir name
		for test_dir in $failed; do
			name=${test_dir#"$dir/"}
			if [[ -f "$test_dir/monkey.md" ]]; then
				cat "$test_dir/monkey.md"
			else
				echo "### $name"
				echo
				echo "Failed before the monkey finished (the page did not open, or the run timed out); see the trace."
			fi
			echo
			[[ ! -f "$test_dir/trace.zip" ]] || echo "Trace: \`$name/trace.zip\`"
			echo
		done
		[[ -n "$failed$reports" ]] || echo "No page reported a failure; see the run logs."
	})
	if ((${#details} > limit)); then
		printf '%s\n```\n\nOutput truncated; the whole report is in the run'"'"'s artifact.\n' "${details:0:limit}"
	else
		printf '%s\n' "$details"
	fi
}

# Opens or comments on the monkey's ci-failure issue after a failed run; closes it after a green one.
cmd_report() {
	local dir=${1:-} issue labels body
	[[ -n "$dir" ]] || usage
	issue=$(gh issue list --label ci-failure --state open --limit 100 --json number,title,body |
		jq -r --arg t "$TITLE" --arg m "$MARKER" \
			'[.[] | select(.title == $t or (.body | contains($m)))] | sort_by(.number) | first | .number // empty')

	if [[ "$(cat "$dir/exit-code" 2>/dev/null)" == 0 ]]; then
		if [[ -z "$issue" ]]; then
			echo "monkey: green; no open issue."
			return
		fi
		gh issue comment "$issue" --body "The nightly monkey run is green again (${RUN_URL:-no run link}). Closing."
		gh issue close "$issue"
		return
	fi

	labels=$(gh label list --limit 500 --json name --jq '.[].name')
	grep -qxF ci-failure <<<"$labels" ||
		gh label create ci-failure --color B60205 --description "A CI or nightly check failed"
	grep -qxF needs-triage <<<"$labels" ||
		gh label create needs-triage --color 1D76DB --description "Maintainer needs to evaluate this issue"
	body=$(cmd_issue_body "$dir")
	if [[ -n "$issue" ]]; then
		gh issue comment "$issue" --body "$body"
		echo "monkey: commented on #$issue."
	else
		gh issue create --title "$TITLE" --label ci-failure --label needs-triage --body "$body"
	fi
}

case ${1:-} in
run)
	shift
	cmd_run "$@"
	;;
issue-body) cmd_issue_body "${2:-}" ;;
report) cmd_report "${2:-}" ;;
*) usage ;;
esac
