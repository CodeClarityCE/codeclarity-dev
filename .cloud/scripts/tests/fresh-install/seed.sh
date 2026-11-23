# shellcheck shell=sh
# The upgrade test's seeded data: made through the API before the upgrade, read back through it after.
# Source it after lib.sh. Keeps the seeded ids and what the API showed of them in $WORK/seed.

SEED_PROJECT=upgrade-seed-app

# Seeds a project from an uploaded archive, a Default Analyzer analysis of it and a ticket on both,
# in org $2, then records what the API shows of them; $1 names the run.
seed_upgrade_data() {
	mkdir -p "$WORK/seed"
	archive="$WORK/seed/app.tar.gz"
	npm_project_archive "$archive"
	result=ok
	s_project=$(post "/org/$2/projects" '{"name":"'"$SEED_PROJECT"'","description":"Seeded before the upgrade"}' | jq -er '.id') || result=bad
	[ "$result" = ok ] && { upload_archive "$2" "$s_project" "$archive" || result=bad; }
	[ "$result" = ok ] && { s_analysis=$(start_analysis "$2" "$s_project") || result=bad; }
	[ "$result" = ok ] && { wait_analysis "$2" "$s_project" "$s_analysis" || result=bad; }
	if [ "$result" = ok ]; then
		body=$(jq -nc --arg p "$s_project" --arg a "$s_analysis" '{title: "Upgrade seed ticket",
			description: "Seeded before the upgrade", priority: "MEDIUM", type: "UPGRADE", project_id: $p,
			source_analysis_id: $a, affected_package: "ms", affected_version: "2.1.3"}')
		s_ticket=$(post "/org/$2/tickets" "$body" | jq -er '.id') || result=bad
	fi
	check "$1: a project, a completed analysis of it and a ticket are seeded through the API" $result
	if [ "$result" = bad ]; then
		jq '.data | {status, steps: [.steps[][] | {name: .Name, status: .Status}]}' "$WORK/analysis.json" 2>/dev/null || :
		return 0
	fi
	echo "$2 $s_project $s_analysis $s_ticket" >"$WORK/seed/ids"
	for kind in project analysis ticket; do seed_view "$kind" >"$WORK/seed/$kind.before" || :; done
	result=ok
	jq -e '(.sbom | index("ms@2.1.3")) and any(.licenses[]; .deps | index("ms@2.1.3"))' \
		"$WORK/seed/analysis.before" >/dev/null 2>&1 || result=bad
	check "$1: the seeded analysis lists ms@2.1.3 in its SBOM and licences" $result
}

# Prints, as sorted JSON, what the API shows of the seeded project, analysis (with its SBOM and
# licences) or ticket, named by $1; fails if the API does not show it.
seed_view() {
	read -r s_org s_project s_analysis s_ticket <"$WORK/seed/ids" || return 1
	results="/org/$s_org/projects/$s_project/analysis/$s_analysis"
	case $1 in
	project) get "/org/$s_org/projects/$s_project" | jq -Se '.data | {id, name, description, added_on}' ;;
	analysis)
		get "/org/$s_org/projects/$s_project/analyses/$s_analysis" >"$WORK/seed/analysis.json" &&
			get "$results/sbom?workspace=.&page=0&entries_per_page=100" >"$WORK/seed/sbom.json" &&
			get "$results/licenses?workspace=.&page=0&entries_per_page=100" >"$WORK/seed/licenses.json" &&
			jq -Sen --slurpfile a "$WORK/seed/analysis.json" --slurpfile s "$WORK/seed/sbom.json" \
				--slurpfile l "$WORK/seed/licenses.json" '{
					analysis: ($a[0].data | {id, status, created_on, steps: [.steps[][] | {Name, Status}]}),
					sbom: ([$s[0].data[] | "\(.name)@\(.version)"] | sort),
					licenses: ([$l[0].data[] | {id, deps: (.deps_using_license | sort)}] | sort_by(.id))}'
		;;
	ticket)
		get "/org/$s_org/tickets/$s_ticket" | jq -Se '.data | {id, title, description, status, priority, type,
			project_id, source_analysis_id, affected_package, affected_version, created_on}'
		;;
	esac
}

# Checks the API still shows the seeded project, analysis and ticket as before the upgrade; $1 names the run.
check_seeded_data() {
	for kind in project analysis ticket; do
		result=ok
		[ -s "$WORK/seed/$kind.before" ] || result=bad
		seed_view "$kind" >"$WORK/seed/$kind.after" 2>/dev/null || result=bad
		cmp -s "$WORK/seed/$kind.before" "$WORK/seed/$kind.after" || result=bad
		check "$1: the seeded $kind is intact" $result
		if [ "$result" = bad ]; then
			diff "$WORK/seed/$kind.before" "$WORK/seed/$kind.after" || :
		fi
	done
}

# Writes the seeded account's login as a shell env file $1 for the upgrade journey (owner-only).
write_journey_login() {
	(
		umask 077
		printf "E2E_LOGIN_EMAIL='%s'\nE2E_LOGIN_PASSWORD='%s'\n" \
			"$(printf '%s' "$LOGIN_EMAIL" | sed "s/'/'\\\\''/g")" \
			"$(printf '%s' "$LOGIN_PASSWORD" | sed "s/'/'\\\\''/g")" >"$1"
	)
}
