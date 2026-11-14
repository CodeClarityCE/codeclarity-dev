#!/usr/bin/env bash
#
# Org setup wizard for CI on GitHub Actions.
# Run it with org-owner gh auth (scopes: admin:org, repo, workflow):
#
#   scripts/setup-github-actions-org.sh --dry-run   # read state, print every write, change nothing
#   scripts/setup-github-actions-org.sh             # apply, asking before each stage
#
# Each stage reads the current state first and skips what is already done, so
# it is safe to re-run. Docker Hub values are read with no echo, sent to gh on
# stdin and never written to disk or logs.

# ── Configuration: rollout is an edit to these variables ──────────────────
ORG="CodeClarityCE"
CENTRAL_REPO=".github"

# Repos that get the release environment with the Docker Hub secrets.
IMAGE_REPOS=(
  "plugin-sbom-javascript"
  "api"
  "frontend"
  "service-dispatcher"
  "service-notifier"
  "service-project-downloader"
  "service-knowledge"
  "service-package-follower"
  "service-scheduler"
  "plugin-sca-vuln-finder"
  "plugin-sca-patching"
  "plugin-codeql"
  "plugin-sbom-php"
  "plugin-sca-license"
)

# Repos whose default branch must pass the ci check. Add a repo only once its
# Actions CI reports ci, or merges to its main block on a check that never runs.
RULESET_REPOS=(
  ".github"
  "codeclarity-dev"
  "deployment"
  "backend"
  "utility-types"
  "utility-node-semver"
  "utility-dbhelper"
  "utility-amqp-helper"
  "utility-boilerplates"
  "plugin-sbom-javascript"
  "api"
  "frontend"
  "service-dispatcher"
  "service-notifier"
  "service-project-downloader"
  "service-knowledge"
  "service-package-follower"
  "service-scheduler"
  "plugin-sca-vuln-finder"
  "plugin-sca-patching"
  "plugin-codeql"
  "plugin-sbom-php"
  "plugin-sca-license"
)

# Actions allowed besides GitHub-owned ones; every action must also be SHA-pinned.
ALLOWED_ACTION_PATTERNS=(
  "CodeClarityCE/*"
  "docker/login-action@*"
  "docker/setup-buildx-action@*"
  "docker/build-push-action@*"
  "ossf/scorecard-action@*"
  "goreleaser/goreleaser-action@*"
  "ruby/setup-ruby@*"
  "licensee/setup-licensed@*"
  "super-linter/super-linter/slim@*"
)

RELEASE_ENV="release"
RELEASE_BRANCH="main"
DOCKERHUB_USER_SECRET="DOCKERHUB_USERNAME"
DOCKERHUB_TOKEN_SECRET="DOCKERHUB_TOKEN"

RULESET_NAME="Require ci check"
CI_CHECK="ci"
# GitHub Actions app id, so only Actions can satisfy the ci check.
CI_CHECK_APP_ID=15368
# org: one org ruleset (GitHub Team or above). repo: one ruleset per repo
# (works on the Free plan). auto: picks by the org's plan.
RULESET_SCOPE="auto"

# Code security configuration attached to every public repo. The built-in one
# turns on CodeQL default setup and is free for public repos.
CODE_SECURITY_CONFIG_NAME="GitHub recommended"
# ───────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────
# Wizard library: delightful, consistent UX, identical across every wizard.
# ──────────────────────────────────────────────────────────────────────────

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
  BLUE=$(tput setaf 4); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
else
  BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; YELLOW=""
fi

# Author sets this at the top of the stages section.
TOTAL_STAGES=0

_STAGE_INDEX=0
ENV_FILE="${ENV_FILE:-.env}"
WRITTEN_ENV=()    # KEYs written to ENV_FILE this run
WRITTEN_SECRET=() # secret NAMEs set this run
SKIPPED=()        # things we couldn't do (e.g. gh missing)

# _clear wipes the terminal so only the current step is on screen. No-op when
# output isn't a terminal, so piped logs stay readable.
_clear() {
  [[ -t 1 ]] || return 0
  if command -v tput >/dev/null 2>&1 && tput clear 2>/dev/null; then return 0; fi
  printf '\033[2J\033[3J\033[H'
}

# banner "Title" shows the opening frame: what this wizard does.
banner() {
  _clear
  printf '\n%s%s  %s%s\n' "$BOLD" "$BLUE" "$1" "$RESET"
  printf '%s  %s stages%s\n\n' "$DIM" "$TOTAL_STAGES" "$RESET"
  printf '%s  You drive the browser; this wizard tells you exactly what to do and\n' "$DIM"
  printf '  captures the values you copy back. Stop any time with Ctrl-C and re-run\n'
  printf '  later, since it remembers values already saved.%s\n' "$RESET"
  pause "Ready to start?"
}

# stage "Name" clears the screen, then announces a stage and shows progress.
# Clearing keeps only the current step on screen.
stage() {
  _clear
  _STAGE_INDEX=$((_STAGE_INDEX + 1))
  printf '\n%s%s▸ Stage %s/%s · %s%s\n' \
    "$BOLD" "$BLUE" "$_STAGE_INDEX" "$TOTAL_STAGES" "$1" "$RESET"
}

# say "..." prints a plain instruction line.
say()  { printf '  %s\n' "$1"; }
# step "..." is a numbered-feeling action the human takes in the browser.
step() { printf '  %s•%s %s\n' "$BLUE" "$RESET" "$1"; }
note() { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }
warn() { printf '  %s⚠ %s%s\n' "$YELLOW" "$1" "$RESET"; }

# open_url URL opens it in the human's browser, cross-platform incl. WSL.
open_url() {
  local url="$1"
  printf '  %s↗ opening%s %s\n' "$GREEN" "$RESET" "$url"
  { if   command -v wslview     >/dev/null 2>&1; then wslview "$url"
    elif command -v explorer.exe >/dev/null 2>&1; then explorer.exe "$url"
    elif command -v xdg-open    >/dev/null 2>&1; then xdg-open "$url"
    elif command -v open        >/dev/null 2>&1; then open "$url"
    else false; fi
  } >/dev/null 2>&1 || warn "couldn't open a browser, so visit it manually: $url"
}

# pause "msg" waits for the human to confirm they've done the manual part.
pause() {
  printf '  %s%s%s ' "$DIM" "${1:-Press Enter to continue}" "$RESET"
  read -r _ || true
}

# confirm "question" is a y/N gate; returns success on yes.
confirm() {
  local reply=""
  printf '  %s? %s [y/N] ' "$YELLOW" "$1"
  read -r reply || true
  [[ "$reply" =~ ^[Yy] ]]
}

# finish clears, then shows a closing summary of everything configured.
finish() {
  _clear
  printf '\n%s%s  ✓ Setup complete%s\n' "$BOLD" "$GREEN" "$RESET"
  (( ${#WRITTEN_ENV[@]} ))    && note "wrote ${#WRITTEN_ENV[@]} value(s) to $ENV_FILE: ${WRITTEN_ENV[*]}"
  (( ${#WRITTEN_SECRET[@]} )) && note "set ${#WRITTEN_SECRET[@]} GitHub secret(s): ${WRITTEN_SECRET[*]}"
  if (( ${#SKIPPED[@]} )); then
    printf '\n'; warn "still to do by hand:"
    for s in "${SKIPPED[@]}"; do note "  - $s"; done
  fi
  printf '\n'
}

# ──────────────────────────────────────────────────────────────────────────
# STAGES: author this section. One stage() per step the human takes.
# Replace the example below. Set TOTAL_STAGES to match the stages you write.
# Keep every stage inside run_wizard and the last line as is: bash then parses
# the whole file before the first prompt, so an edit mid-run can't break it.
# ──────────────────────────────────────────────────────────────────────────

DRY_RUN=false
APPLIED=()
GH_ERR=""
GH_STATUS=""
PLAN_METHOD=()
PLAN_PATH=()
PLAN_BODY=()
PLAN_DESC=()
PLAN_DECLINED=false

usage() {
  printf 'Usage: %s [--dry-run]\n' "$0"
}

# dry "..." prints a line that only appears in dry-run mode.
dry() { printf '  %s[dry-run]%s %s\n' "$YELLOW" "$RESET" "$1"; }
ok()  { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$1"; }

# gate "question": y/N prompt in a real run, always yes in dry-run.
gate() {
  if $DRY_RUN; then dry "would ask: $1"; return 0; fi
  confirm "$1"
}

# gh_get VAR PATH [JQ]: reads a GitHub API path into VAR (all pages when JQ is
# given). Returns 0 on success, 4 on 404, 1 on other errors (see GH_ERR).
gh_get() {
  local var="$1" path="$2" filter="${3:-}" out errfile rc=0
  printf '  %sGET %s%s\n' "$DIM" "$path" "$RESET"
  errfile=$(mktemp)
  if [[ -n "$filter" ]]; then
    out=$(gh api --paginate "$path" --jq "$filter" 2>"$errfile") || rc=$?
  else
    out=$(gh api "$path" 2>"$errfile") || rc=$?
  fi
  GH_ERR=$(grep -m1 '^gh: ' "$errfile" | sed 's/^gh: //' || true)
  rm -f "$errfile"
  printf -v "$var" '%s' "$out"
  if (( rc == 0 )); then GH_STATUS=200; return 0; fi
  GH_STATUS=$(sed -n 's/.*(HTTP \([0-9]*\)).*/\1/p' <<<"$GH_ERR")
  [[ "$GH_STATUS" == "404" ]] && return 4
  return 1
}

# unknown_state "what": a read failed. Dry-run carries on as if nothing is set;
# a real run stops, since writing blind is not safe.
unknown_state() {
  warn "could not read $1: ${GH_ERR:-unknown error}"
  if $DRY_RUN; then
    dry "treating $1 as not configured"
    return 0
  fi
  SKIPPED+=("$1 (read failed: ${GH_ERR:-unknown error})")
  return 1
}

# plan METHOD PATH BODY "description" queues one write for apply_plan.
plan() {
  PLAN_METHOD+=("$1"); PLAN_PATH+=("$2"); PLAN_BODY+=("$3"); PLAN_DESC+=("$4")
}

# apply_plan shows the queued writes, asks once, then runs them in order.
# Sets PLAN_DECLINED when the maintainer says no.
apply_plan() {
  local i n=${#PLAN_METHOD[@]}
  PLAN_DECLINED=false
  if (( n == 0 )); then ok "nothing to change"; return 0; fi
  say ""
  say "${BOLD}Will change:${RESET}"
  for (( i = 0; i < n; i++ )); do step "${PLAN_DESC[$i]}"; done
  say ""
  if gate "Apply these $n change(s)?"; then
    for (( i = 0; i < n; i++ )); do
      api_write "${PLAN_METHOD[$i]}" "${PLAN_PATH[$i]}" "${PLAN_BODY[$i]}" || {
        warn "stopped: ${PLAN_DESC[$i]} failed"
        SKIPPED+=("${PLAN_DESC[$i]}")
        PLAN_METHOD=(); PLAN_PATH=(); PLAN_BODY=(); PLAN_DESC=()
        return 1
      }
      $DRY_RUN || APPLIED+=("${PLAN_DESC[$i]}")
    done
  else
    PLAN_DECLINED=true
    for (( i = 0; i < n; i++ )); do SKIPPED+=("${PLAN_DESC[$i]}"); done
  fi
  PLAN_METHOD=(); PLAN_PATH=(); PLAN_BODY=(); PLAN_DESC=()
}

# api_write METHOD PATH [BODY] sends one write, or prints it in dry-run.
api_write() {
  local method="$1" path="$2" body="${3:-}"
  if $DRY_RUN; then
    if [[ -n "$body" ]]; then
      dry "gh api -X $method $path --input - <<'JSON'"
      jq . <<<"$body" | sed 's/^/      /'
      printf '      JSON\n'
    else
      dry "gh api -X $method $path"
    fi
    return 0
  fi
  if [[ -n "$body" ]]; then
    printf '%s' "$body" | gh api -X "$method" "$path" --input - >/dev/null
  else
    gh api -X "$method" "$path" >/dev/null
  fi
  ok "$method $path"
}

# json_array ITEM...: prints the items as a JSON array of strings.
json_array() { jq -cn '$ARGS.positional' --args "$@"; }

# ── Stage: preflight ──────────────────────────────────────────────────────
stage_preflight() {
  stage "Check tools and gh auth"
  local missing=() scopes
  command -v gh >/dev/null 2>&1 || missing+=("gh")
  command -v jq >/dev/null 2>&1 || missing+=("jq")
  if (( ${#missing[@]} )); then
    warn "missing: ${missing[*]}; install them and re-run"
    exit 1
  fi
  if ! gh auth status >/dev/null 2>&1; then
    warn "gh is not logged in; run: gh auth login -h github.com -s admin:org,repo,workflow"
    exit 1
  fi
  scopes=$(gh api -i user 2>/dev/null | sed -n 's/^[Xx]-[Oo][Aa]uth-[Ss]copes: *//p' | tr -d '\r')
  if [[ -z "$scopes" ]]; then
    note "token scopes not reported (fine-grained token?); org writes need org admin rights"
  else
    say "token scopes: $scopes"
    local need
    for need in admin:org repo workflow; do
      if [[ ",${scopes// /}," != *",$need,"* ]]; then
        warn "token lacks $need; run: gh auth refresh -h github.com -s $need"
        $DRY_RUN || exit 1
      fi
    done
  fi
  ok "gh and jq ready"
  $DRY_RUN || pause "Press Enter to continue"
}

# ── Stage: central repo ───────────────────────────────────────────────────
stage_central_repo() {
  stage "Central repo $ORG/$CENTRAL_REPO (public, main and develop)"
  local repo="$ORG/$CENTRAL_REPO" info rc=0 visibility files sha
  gh_get info "repos/$repo" || rc=$?
  if (( rc == 4 )); then
    say "$repo does not exist yet."
    plan POST "orgs/$ORG/repos" \
      "$(jq -cn --arg n "$CENTRAL_REPO" '{name: $n, visibility: "public", auto_init: true,
         description: "Central reusable GitHub Actions workflows for CodeClarityCE"}')" \
      "create public repo $repo with an initial main branch"
    apply_plan || return 0
  elif (( rc != 0 )); then
    unknown_state "repo $repo" || return 0
  else
    visibility=$(jq -r .visibility <<<"$info")
    if [[ "$visibility" == "public" ]]; then
      ok "$repo exists and is public"
    else
      warn "$repo exists but is $visibility."
      say "Making it public publishes its whole git history. Current top-level files:"
      if gh_get files "repos/$repo/contents" '.[].path'; then
        while IFS= read -r f; do [[ -n "$f" ]] && note "    $f"; done <<<"$files"
      fi
      plan PATCH "repos/$repo" '{"visibility":"public"}' "make $repo public"
      apply_plan || return 0
    fi
  fi

  # develop is branched from the current main.
  rc=0
  gh_get info "repos/$repo/branches/develop" || rc=$?
  if (( rc == 0 )); then ok "develop exists"; return 0; fi
  if (( rc != 4 )); then unknown_state "branch develop of $repo" || return 0; fi
  rc=0
  gh_get sha "repos/$repo/git/ref/heads/main" '.object.sha' || rc=$?
  if (( rc != 0 )) || [[ -z "$sha" ]]; then
    if $DRY_RUN; then sha="<sha of main>"; else unknown_state "main of $repo"; return 0; fi
  fi
  plan POST "repos/$repo/git/refs" \
    "$(jq -cn --arg s "$sha" '{ref: "refs/heads/develop", sha: $s}')" \
    "create branch develop in $repo from main ($sha)"
  apply_plan || true
}

# ── Stage: allowed actions ────────────────────────────────────────────────
stage_actions_policy() {
  stage "Actions policy: GitHub-owned and listed actions, SHA-pinned"
  say "Allowed: GitHub-owned actions plus: ${ALLOWED_ACTION_PATTERNS[*]}"
  say "Every action must be pinned to a full commit SHA (reusable workflows may use tags)."
  warn "This applies to every repo now: workflows using unpinned or unlisted actions"
  warn "(e.g. tj-actions/branch-names, codeclarity-action@v0) stop running."
  local cur rc=0 enabled="all" desired want have
  gh_get cur "orgs/$ORG/actions/permissions" || rc=$?
  if (( rc == 0 )); then
    enabled=$(jq -r .enabled_repositories <<<"$cur")
    if [[ "$(jq -r '"\(.allowed_actions) \(.sha_pinning_required // false)"' <<<"$cur")" == "selected true" ]]; then
      ok "allowed_actions=selected, sha_pinning_required=true"
    else
      rc=1
    fi
  else
    unknown_state "org Actions permissions" || return 0
    rc=1
  fi
  if (( rc != 0 )); then
    # Keeps which repos may run Actions as it is.
    plan PUT "orgs/$ORG/actions/permissions" \
      "$(jq -cn --arg e "$enabled" '{enabled_repositories: $e, allowed_actions: "selected", sha_pinning_required: true}')" \
      "allow only selected actions and require SHA pins (enabled_repositories stays $enabled)"
  fi

  desired=$(jq -cn --argjson p "$(json_array "${ALLOWED_ACTION_PATTERNS[@]}")" \
    '{github_owned_allowed: true, verified_allowed: false, patterns_allowed: $p}')
  want=$(jq -c '.patterns_allowed |= sort' <<<"$desired")
  rc=0
  if (( ${#PLAN_METHOD[@]} == 0 )) && gh_get cur "orgs/$ORG/actions/permissions/selected-actions"; then
    have=$(jq -c '{github_owned_allowed, verified_allowed, patterns_allowed: ((.patterns_allowed // []) | sort)}' <<<"$cur")
    if [[ "$have" == "$want" ]]; then ok "allowed action patterns match"; else rc=1; fi
  elif (( ${#PLAN_METHOD[@]} == 0 )); then
    unknown_state "org selected actions" || return 0
    rc=1
  else
    rc=1
  fi
  if (( rc != 0 )); then
    plan PUT "orgs/$ORG/actions/permissions/selected-actions" "$desired" \
      "allow GitHub-owned actions and ${#ALLOWED_ACTION_PATTERNS[@]} pattern(s), not all verified creators"
  fi
  apply_plan || true
}

# ── Stage: workflow token ─────────────────────────────────────────────────
stage_workflow_token() {
  stage "Default workflow token: read-only, cannot approve PRs"
  local cur rc=0
  gh_get cur "orgs/$ORG/actions/permissions/workflow" || rc=$?
  if (( rc == 0 )) && [[ "$(jq -r '"\(.default_workflow_permissions) \(.can_approve_pull_request_reviews)"' <<<"$cur")" == "read false" ]]; then
    ok "already read-only and unable to approve PRs"
    return 0
  fi
  if (( rc != 0 )); then unknown_state "org workflow token permissions" || return 0; fi
  plan PUT "orgs/$ORG/actions/permissions/workflow" \
    '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}' \
    "set the default GITHUB_TOKEN to read and forbid workflow PR approvals"
  apply_plan || true
}

# ── Stage: CodeQL ─────────────────────────────────────────────────────────
stage_codeql() {
  stage "CodeQL default setup on every public repo"
  say "Attaches the \"$CODE_SECURITY_CONFIG_NAME\" code security configuration to public repos"
  say "and makes it the default for new public repos. It also turns on Dependabot alerts,"
  say "secret scanning with push protection and private vulnerability reporting, all free"
  say "for public repos. Private repos are left alone."
  local configs cfg_id repos need_ids=() need_names=() id name attached defaults rc=0
  gh_get configs "orgs/$ORG/code-security/configurations" || rc=$?
  if (( rc != 0 )); then unknown_state "code security configurations" || return 0; fi
  cfg_id=$(jq -r --arg n "$CODE_SECURITY_CONFIG_NAME" '[.[]? | select(.name == $n)][0].id // empty' <<<"${configs:-[]}")
  if [[ -z "$cfg_id" ]]; then
    warn "no configuration named \"$CODE_SECURITY_CONFIG_NAME\"; create it in the org settings or fix CODE_SECURITY_CONFIG_NAME"
    if ! $DRY_RUN; then SKIPPED+=("CodeQL: configuration not found"); return 0; fi
    cfg_id="<config id>"
  fi
  [[ "$(jq -r --arg n "$CODE_SECURITY_CONFIG_NAME" '[.[]? | select(.name == $n)][0].code_scanning_default_setup // ""' <<<"${configs:-[]}")" == "enabled" ]] \
    || $DRY_RUN || warn "\"$CODE_SECURITY_CONFIG_NAME\" does not enable code_scanning_default_setup"

  gh_get repos "orgs/$ORG/repos?type=public&per_page=100" \
    '.[] | select(.archived | not) | select(.fork | not) | "\(.id) \(.name)"' \
    || { unknown_state "public repo list" || return 0; }
  while read -r id name; do
    [[ -n "$id" ]] || continue
    attached=""
    gh_get attached "repos/$ORG/$name/code-security-configuration" '.configuration.id // empty' || true
    if [[ "$attached" != "$cfg_id" ]]; then need_ids+=("$id"); need_names+=("$name"); fi
  done <<<"$repos"

  if (( ${#need_ids[@]} )); then
    plan POST "orgs/$ORG/code-security/configurations/$cfg_id/attach" \
      "$(jq -cn --argjson ids "[$(IFS=,; printf '%s' "${need_ids[*]}")]" '{scope: "selected", selected_repository_ids: $ids}')" \
      "attach \"$CODE_SECURITY_CONFIG_NAME\" to ${#need_ids[@]} public repo(s): ${need_names[*]}"
  else
    ok "every public repo already uses \"$CODE_SECURITY_CONFIG_NAME\""
  fi

  rc=0
  gh_get defaults "orgs/$ORG/code-security/configurations/defaults" \
    '.[]? | select(.default_for_new_repos == "public" or .default_for_new_repos == "all") | .configuration.id' || rc=$?
  if (( rc != 0 )); then unknown_state "default code security configuration" || return 0; fi
  if grep -qx "$cfg_id" <<<"$defaults"; then
    ok "already the default for new public repos"
  else
    plan PUT "orgs/$ORG/code-security/configurations/$cfg_id/defaults" \
      '{"default_for_new_repos":"public"}' \
      "make \"$CODE_SECURITY_CONFIG_NAME\" the default for new public repos"
  fi
  apply_plan || true
}

# ── Stage: release environments ───────────────────────────────────────────
# set_env_secret REPO NAME VALUE sends VALUE to gh on stdin, never as an argument.
set_env_secret() {
  local repo="$1" name="$2" value="$3"
  if $DRY_RUN; then
    dry "gh secret set $name --env $RELEASE_ENV --repo $repo   (value read from a hidden prompt, sent on stdin)"
    return 0
  fi
  if gh secret set "$name" --env "$RELEASE_ENV" --repo "$repo" < <(printf '%s' "$value") >/dev/null; then
    ok "set $name in $repo ($RELEASE_ENV)"
    WRITTEN_SECRET+=("$repo:$RELEASE_ENV/$name")
  else
    warn "could not set $name in $repo"
    SKIPPED+=("secret $name in $repo ($RELEASE_ENV)")
  fi
}

stage_environments() {
  stage "Environment \"$RELEASE_ENV\" (only $RELEASE_BRANCH) with Docker Hub secrets"
  say "Repos: ${IMAGE_REPOS[*]}"
  local r repo env rc policies names need_secrets=() env_ready=() missing pid pname
  for r in "${IMAGE_REPOS[@]}"; do
    repo="$ORG/$r"
    say ""
    say "${BOLD}$repo${RESET}"
    rc=0
    gh_get env "repos/$repo/environments/$RELEASE_ENV" || rc=$?
    if (( rc == 1 )); then unknown_state "environment $RELEASE_ENV of $repo" || continue; fi
    if (( rc == 0 )) && [[ "$(jq -c '.deployment_branch_policy | {protected_branches, custom_branch_policies}' <<<"$env")" == '{"protected_branches":false,"custom_branch_policies":true}' ]]; then
      ok "environment exists with custom branch policies"
    else
      plan PUT "repos/$repo/environments/$RELEASE_ENV" \
        '{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' \
        "create or update environment $RELEASE_ENV in $repo with custom branch policies"
    fi

    policies=""
    if (( rc == 0 )); then
      gh_get policies "repos/$repo/environments/$RELEASE_ENV/deployment-branch-policies" \
        '.branch_policies[]? | "\(.id) \(.type // "branch") \(.name)"' \
        || { unknown_state "branch policies of $repo" || continue; }
    fi
    if ! grep -qx "[0-9]* branch $RELEASE_BRANCH" <<<"$policies"; then
      plan POST "repos/$repo/environments/$RELEASE_ENV/deployment-branch-policies" \
        "$(jq -cn --arg b "$RELEASE_BRANCH" '{name: $b, type: "branch"}')" \
        "allow branch $RELEASE_BRANCH to deploy to $RELEASE_ENV in $repo"
    else
      ok "branch policy $RELEASE_BRANCH present"
    fi
    # Any other branch or tag policy would widen who can read the secrets.
    while read -r pid _ pname; do
      [[ -n "$pid" ]] || continue
      [[ "$pname" == "$RELEASE_BRANCH" ]] && continue
      plan DELETE "repos/$repo/environments/$RELEASE_ENV/deployment-branch-policies/$pid" "" \
        "remove extra deployment policy \"$pname\" from $RELEASE_ENV in $repo"
    done < <(grep -vx "[0-9]* branch $RELEASE_BRANCH" <<<"$policies" || true)
    apply_plan || continue
    # Declined: the environment may be missing or unprotected, so leave its secrets alone.
    if $PLAN_DECLINED; then
      note "environment $RELEASE_ENV not set up in $repo; skipping its secrets"
      SKIPPED+=("Docker Hub secrets for $r (environment declined)")
      continue
    fi
    env_ready+=("$r")

    names=""
    if (( rc == 0 )); then
      gh_get names "repos/$repo/environments/$RELEASE_ENV/secrets" '.secrets[]?.name' || true
    fi
    missing=""
    grep -qx "$DOCKERHUB_USER_SECRET" <<<"$names" || missing+=" $DOCKERHUB_USER_SECRET"
    grep -qx "$DOCKERHUB_TOKEN_SECRET" <<<"$names" || missing+=" $DOCKERHUB_TOKEN_SECRET"
    if [[ -n "$missing" ]]; then
      say "missing secrets:$missing"
      need_secrets+=("$r")
    else
      ok "$DOCKERHUB_USER_SECRET and $DOCKERHUB_TOKEN_SECRET present"
    fi
  done

  say ""
  if (( ${#env_ready[@]} == 0 )); then
    note "no repo has the $RELEASE_ENV environment; skipping secrets"
    return 0
  fi
  if (( ${#need_secrets[@]} == 0 )); then
    gate "All secrets are set. Replace them with new Docker Hub values (rotation)?" || return 0
    $DRY_RUN && { dry "a real run defaults to No here"; return 0; }
    need_secrets=("${env_ready[@]}")
  fi
  say "Secrets go to: ${need_secrets[*]}"
  step "Docker Hub: Account settings, Personal access tokens, Generate new token."
  step "Give it Read & Write access, copy it, and have the account username ready."
  if $DRY_RUN; then
    dry "would open https://app.docker.com/settings/personal-access-tokens"
  else
    open_url "https://app.docker.com/settings/personal-access-tokens"
  fi
  if $DRY_RUN; then
    dry "would read $DOCKERHUB_USER_SECRET and $DOCKERHUB_TOKEN_SECRET with read -rs (no echo)"
    for r in "${need_secrets[@]}"; do
      set_env_secret "$ORG/$r" "$DOCKERHUB_USER_SECRET" ""
      set_env_secret "$ORG/$r" "$DOCKERHUB_TOKEN_SECRET" ""
    done
    return 0
  fi
  local hub_user="" hub_token=""
  printf '  %sDocker Hub username:%s ' "$BOLD" "$RESET"; read -rs hub_user || true; printf '\n'
  printf '  %sDocker Hub token:%s ' "$BOLD" "$RESET"; read -rs hub_token || true; printf '\n'
  if [[ -z "$hub_user" || -z "$hub_token" ]]; then
    warn "empty value; secrets not set"
    SKIPPED+=("Docker Hub secrets for: ${need_secrets[*]}")
    return 0
  fi
  if gate "Set both secrets in: ${need_secrets[*]}?"; then
    for r in "${need_secrets[@]}"; do
      set_env_secret "$ORG/$r" "$DOCKERHUB_USER_SECRET" "$hub_user"
      set_env_secret "$ORG/$r" "$DOCKERHUB_TOKEN_SECRET" "$hub_token"
    done
  else
    SKIPPED+=("Docker Hub secrets for: ${need_secrets[*]}")
  fi
  unset hub_user hub_token
}

# ── Stage: ruleset ────────────────────────────────────────────────────────
# ruleset_body INCLUDE_JSON: the desired ruleset; INCLUDE_JSON is null for a repo ruleset.
ruleset_body() {
  jq -cn --arg name "$RULESET_NAME" --arg ctx "$CI_CHECK" --argjson app "$CI_CHECK_APP_ID" \
    --argjson repos "$1" '{
      name: $name, target: "branch", enforcement: "active", bypass_actors: [],
      conditions: ({ref_name: {include: ["~DEFAULT_BRANCH"], exclude: []}}
        + (if $repos == null then {} else
           {repository_name: {include: $repos, exclude: [], protected: false}} end)),
      rules: [{type: "required_status_checks", parameters: {
        strict_required_status_checks_policy: false,
        do_not_enforce_on_create: true,
        required_status_checks: [{context: $ctx, integration_id: $app}]}}]}'
}

# ruleset_key JSON: the fields that matter, normalized for comparison.
ruleset_key() {
  jq -c '{enforcement, refs: (.conditions.ref_name.include | sort),
    repos: ((.conditions.repository_name.include // []) | sort),
    rules: [.rules[] | {type, checks: ([.parameters.required_status_checks[]? | "\(.context)@\(.integration_id)"] | sort),
      strict: (.parameters.strict_required_status_checks_policy // false)}]}' <<<"$1"
}

# sync_ruleset BASE QUERY BODY: creates or updates the named ruleset under BASE.
sync_ruleset() {
  local prefix="$1" query="$2" body="$3" id cur rc=0
  gh_get id "$prefix$query" ".[]? | select(.name == \"$RULESET_NAME\") | .id" || rc=$?
  if (( rc != 0 )); then unknown_state "rulesets at $prefix" || return 0; id=""; fi
  id=$(head -n1 <<<"$id")
  if [[ -z "$id" ]]; then
    plan POST "$prefix" "$body" "create ruleset \"$RULESET_NAME\" at $prefix"
    return 0
  fi
  gh_get cur "$prefix/$id" || { unknown_state "ruleset $id" || return 0; }
  if [[ "$(ruleset_key "$cur")" == "$(ruleset_key "$body")" ]]; then
    ok "ruleset \"$RULESET_NAME\" ($id) is up to date"
  else
    plan PUT "$prefix/$id" "$body" "update ruleset \"$RULESET_NAME\" ($id)"
  fi
}

stage_ruleset() {
  stage "Ruleset: require the $CI_CHECK check on the default branch"
  say "Repos: ${RULESET_REPOS[*]}"
  local scope="$RULESET_SCOPE" plan_name r branch runs no_ci=() repos=()
  if [[ "$scope" == "auto" ]]; then
    gh_get plan_name "orgs/$ORG" '.plan.name // ""' || true
    if [[ -z "$plan_name" || "$plan_name" == "free" ]]; then scope="repo"; else scope="org"; fi
    say "org plan: ${plan_name:-unknown}, so using $scope-level rulesets"
  fi

  # A repo whose ci never reported would have its merges blocked.
  for r in "${RULESET_REPOS[@]}"; do
    branch=""
    gh_get branch "repos/$ORG/$r" '.default_branch' || { warn "cannot read $ORG/$r; leaving it out"; continue; }
    repos+=("$r")
    runs=0
    gh_get runs "repos/$ORG/$r/commits/$branch/check-runs?check_name=$CI_CHECK&per_page=1" '.total_count' || true
    if [[ "${runs:-0}" == 0 ]]; then
      gh_get runs "repos/$ORG/$r/commits/develop/check-runs?check_name=$CI_CHECK&per_page=1" '.total_count' || true
    fi
    [[ "${runs:-0}" =~ ^[1-9] ]] || no_ci+=("$r")
  done
  if (( ${#no_ci[@]} )); then
    warn "no $CI_CHECK check has reported yet on: ${no_ci[*]}"
    warn "requiring it now would block their merges to the default branch."
    if $DRY_RUN; then
      dry "a real run asks whether to leave these out; showing the full list here"
    elif confirm "Leave them out for now (recommended; re-run once their CI reports)?"; then
      local keep=() x
      for x in "${repos[@]}"; do [[ " ${no_ci[*]} " == *" $x "* ]] || keep+=("$x"); done
      repos=("${keep[@]}")
    fi
  fi
  if (( ${#repos[@]} == 0 )); then
    note "no repos to protect yet; skipping"
    SKIPPED+=("ruleset: no repo has reported $CI_CHECK yet")
    return 0
  fi

  if [[ "$scope" == "org" ]]; then
    sync_ruleset "orgs/$ORG/rulesets" "" "$(ruleset_body "$(json_array "${repos[@]}")")"
  else
    note "repo-level rulesets: a repo dropped from the list keeps its ruleset until removed by hand"
    for r in "${repos[@]}"; do
      sync_ruleset "repos/$ORG/$r/rulesets" "?includes_parents=false" "$(ruleset_body null)"
    done
  fi
  apply_plan || true
}

run_wizard() {

case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=true ;;
  -h|--help) usage; return 0 ;;
  *) usage; return 1 ;;
esac

TOTAL_STAGES=7

if $DRY_RUN; then
  # Keep the whole dry-run on screen.
  _clear() { :; }
  printf '\n%s%s  GitHub Actions org setup for %s (dry run)%s\n' "$BOLD" "$BLUE" "$ORG" "$RESET"
  note "Reads current state with GET; prints every write instead of sending it."
else
  banner "GitHub Actions org setup for $ORG"
fi

stage_preflight
stage_central_repo
stage_actions_policy
stage_workflow_token
stage_codeql
stage_environments
stage_ruleset

if $DRY_RUN; then
  printf '\n%s%s  Dry run complete: nothing was changed%s\n\n' "$BOLD" "$GREEN" "$RESET"
  return 0
fi
finish
(( ${#APPLIED[@]} )) && { note "applied:"; for a in "${APPLIED[@]}"; do note "  - $a"; done; printf '\n'; }
return 0
}

run_wizard "$@"; exit
