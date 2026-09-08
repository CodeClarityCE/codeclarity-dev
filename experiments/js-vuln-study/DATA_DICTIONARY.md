# Data dictionary

Column-by-column reference for every artifact the harness writes, under a
study directory (e.g. `studies/top100/`). Producers: `run.py run` maintains
`manifest.jsonl` and `run_meta.jsonl`; `run.py analyze` derives everything
under `tables/` from them plus the raw plugin blobs in `raw/`, and renders
`report/brief.pdf`.

A **rung or cohort study** (`study.toml` sets `frozen_from`) has the same
layout, minus `sample.json`: its rows are populated by `run.py run` reading
another study's `manifest.jsonl` read-only, `snapshot_date` carried over
verbatim from the source rows (deduped by `(git_url, commit_hash)`, so join
cross-rung on those two columns, not on `snapshot_date`), and `skipped` rows
may carry the reason `no pinned commit in source` for source rows without a
`commit_hash`.

Read the semantic notes, not just the column names: several fields are easy
to misread (instances vs unique packages, resolved multiset vs install set,
heuristic flags).

## manifest.jsonl

One JSON line per attempted `(project, snapshot)` pair, the run's source of
truth. New rows are appended by `run`; an existing row is replaced in place
(atomic whole-file rewrite) on every state transition. Fields mirror `Row`
in `js_vuln_study/manifest.py`.

| Field | Type | Meaning |
|-------|------|---------|
| `npm_name` | str | Canonical `owner/repo` slug: the CodeClarity project name and the join key used across all tables. |
| `tier` | str | The study's name (e.g. `"top100"`, `"passbolt"`). |
| `rank` | int | 0-based star rank within the sample (0 = most-starred). |
| `git_url` | str | Canonical GitHub URL; half of the `(git_url, snapshot_date)` dedup key. |
| `branch` | str \| null | Default branch the analysis was submitted on. Null for `skipped` rows. |
| `snapshot_date` | str | `"YYYY-MM-DD"` grid date, `"HEAD"`, or `"*"`, the sentinel for project-wide `skipped` rows recorded before any snapshot was known. |
| `commit_hash` | str \| null | The exact commit analysed. `"HEAD"` rows carry the branch-tip SHA pinned at submit time; null for `skipped` rows and for a HEAD row whose resolution itself failed (which is `skipped`, not submitted unpinned). |
| `committed_at` | str \| null | ISO commit timestamp of `commit_hash`, when known. |
| `project_id` | str \| null | CodeClarity project UUID. Null for drops recorded before import. |
| `analysis_id` | str \| null | CodeClarity analysis UUID. Null for `skipped` rows and POST failures. |
| `state` | str | One of `pending`, `done`, `failed`, `skipped`. See below. |
| `server_status` | str \| null | The API's raw status word for the row's last transition (e.g. `completed`, `failure`), or (for a row normalized from an older manifest) the legacy status word itself. Null for rows that never reached the server. |
| `error` | str \| null | Failure detail for sad rows: the server's `failure_reason`, a plugin `public_error`, the client-side ceiling verdict, or the skip reason. |
| `attempts` | int | How many times a `failed` row has been re-submitted by `retry`/`retry_one`. Retry stops once this reaches `study.toml`'s `retries`. |
| `knowledge_asof` | str \| null | YYYY-MM-DD knowledge cutoff the analysis was submitted under: vuln-finder drops advisories published after this day at match time. Null = no cutoff (full current knowledge DB). Recorded per row so a retry can reuse the row's own cutoff rather than the study's current one. |
| `run_id` | str \| null | The `run()` invocation that (re-)submitted this row; joins to `run_meta.jsonl`. |
| `submitted_at`, `terminal_at` | str \| null | ISO-UTC stamps: when the POST succeeded and when `poll` observed a terminal state. |

### State vocabulary

| State | Meaning |
|-------|---------|
| `pending` | Analysis POSTed and in flight; `poll` drives it. |
| `done` | Server finished successfully (`completed`/`success`); results persisted under `raw/{project_id}/{analysis_id}/`. Only these rows feed the Parquet tables. |
| `failed` | Server-side terminal failure (`failure`/`failed`/`cancelled`), a POST failure (`analysis_id` is null), or a client-side ceiling give-up (`error` starts with `client ceiling:`). |
| `skipped` | Dropped before or during submission: snapshot-resolution failure (project-wide, `snapshot_date == "*"`), HEAD-resolution failure (that row only), import failure, or (for `frozen_from` studies) no pinned commit in the source. |

An older manifest's eight-value vocabulary (`submitted`, `completed`,
`success`, `failure`, `failed`, `cancelled`, `failed-submit`, `skipped`) is
normalized onto these four on read (`manifest.normalize_status`), so an
archived manifest from before this simplification still loads: `submitted`
-> `pending`; `completed`/`success` -> `done`; `failure`/`failed`/
`cancelled`/`failed-submit` -> `failed`; `skipped` -> `skipped`. The legacy
word is preserved in `server_status`.

## run_meta.jsonl and tables/run_meta.json

One JSON line appended per `run`/`refresh-head` invocation
(`pipeline.record_provenance`); `analyze` copies the **latest** record to
`tables/run_meta.json` so a dataset always carries its provenance, and warns
when records disagree on the knowledge-DB snapshot.

| Field | Type | Meaning |
|-------|------|---------|
| `ts` | str | ISO UTC timestamp of the invocation. |
| `run_id` | str | Random UUID per invocation; matches manifest rows' `run_id`. |
| `experiment_sha` | str \| null | Monorepo HEAD commit at run time. |
| `experiment_dirty` | bool \| null | Whether the monorepo working tree had uncommitted changes. |
| `api_sha`, `backend_sha` | str \| null | HEAD commits of the `api/` and `backend/` submodules. |
| `api_version` | str \| null | `api/package.json` version. |
| `org_id`, `analyzer_id` | str | The org/analyzer the run used. |
| `analyzer_steps` | list \| null | The analyzer's *actual* `[[{name, version}], ...]` stages, read back from the API, not the versions the study asked for. |
| `knowledge.knowledge_sources` | dict \| null | Last-update ISO timestamp per knowledge source (null = never updated). This is the vulnerability-data snapshot the run's counts depend on. |
| `knowledge.epss_rows` | int \| null | Row count of the EPSS table at run time. 0 means `epss_score`/`epss_percentile` will be empty. |
| `config.snapshot_dates` | list | The grid in effect (`study.grid`, derived from `study.toml`'s `[grid]` table). |
| `config.knowledge_asof` | str \| null | The study's configured cutoff. |
| `cmd` | str | `"submit"` or `"refresh-head"`. |

Every probe is best-effort (missing git, an older API): any field may be
null (with a logged warning) rather than failing the run.

## tables/analyses.parquet

One row per **done** `(project, snapshot)` scan. Failed/skipped attempts are
*not* here: see `coverage_dropped.csv`.

| Column | Type | Meaning |
|--------|------|---------|
| `analysis_id`, `project_id` | str | CodeClarity UUIDs; join keys to `vulns.parquet`. |
| `npm_name`, `tier`, `rank`, `git_url` | | Copied from the manifest (see above). |
| `snapshot_date` | str | Grid date or `"HEAD"`. HEAD rows carry the pinned `commit_hash`. |
| `commit_hash`, `committed_at` | str \| null | Exact commit analysed and its timestamp. |
| `run_id` | str \| null | The manifest row's `run_id`. |
| `total_dependencies` | int | Size of the resolved dependency multiset: every (workspace, package, version) entry in the SBOM. Not the active install set: a version that appears in the lockfile universe but is not installed still counts. Use as a bloat proxy only. |
| `direct_dependencies`, `transitive_dependencies` | int | Multiset entries flagged `Direct`/`Transitive` by js-sbom. Not mutually exclusive with each other or exhaustive of `total_dependencies`. |
| `dev_dependencies`, `prod_dependencies` | int | Multiset entries flagged `Dev`/`Prod`. |
| `package_manager` | str \| null | Detected by js-sbom (`NPM`/`PNPM`/`YARN`), from the lockfile present. |
| `total_vulnerabilities` | int | Vulnerability *instances*: one per (vulnerability id, affected dependency, workspace) finding. Equals this analysis's row count in `vulns.parquet`. |
| `vulnerable_dependencies` | int | Number of unique affected package names. |
| `direct_vulnerabilities`, `transitive_vulnerabilities` | int | Instances split by the `direct_dependency` flag. Sum to `total_vulnerabilities`. |
| `n_critical`, `n_high`, `n_medium`, `n_low`, `n_none` | int | Instances per CVSS severity class. |

Per-step dispatch timing columns and the per-dependency `dependencies.parquet`
table, produced before this simplification, are no longer written: nothing
in `results_numbers.json` or the brief reads them.

## tables/vulns.parquet

One row per **vulnerability instance**: a (vulnerability id, affected
dependency, workspace) tuple within one analysis. A project scanned at N
snapshots contributes up to N rows for a single persistent CVE; filter on
`snapshot_date` before any cross-sectional statistic.

| Column | Type | Meaning |
|--------|------|---------|
| `analysis_id` ... `committed_at` | | The manifest-derived columns, same as `analyses.parquet`. |
| `workspace` | str | SBOM workspace the finding belongs to (`.` for single-package repos). |
| `vulnerability_id` | str | Advisory id, usually `CVE-...`, sometimes `GHSA-...`/OSV-native. |
| `affected_dependency` | str | Package name the advisory matched. |
| `affected_version` | str | Resolved version of that package in this scan. |
| `severity_class` | str \| null | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`NONE`. |
| `severity_score` | float \| null | CVSS base score. |
| `severity_vector` | str \| null | CVSS vector string. |
| `impact`, `exploitability` | float \| null | CVSS sub-scores. |
| `epss_score`, `epss_percentile` | float \| null | Exploit-prediction score/percentile from the knowledge DB's EPSS table as of analysis time. Empty for non-CVE ids and when `epss_rows` was 0. |
| `conflict_flag` | str \| null | Cross-source match confidence: `MATCH_CORRECT`, `MATCH_INCORRECT`, `MATCH_POSSIBLE_INCORRECT`, `NO_CONFLICT`. |
| `winning_source` | str \| null | Which source's record won conflict resolution: `NVD`, `OSV`, `GCVE`, or `NONE`. |
| `direct_dependency` | bool | Heuristic flag from the SBOM: whether the affected package is declared as a direct dependency. Not a precise install-tree measure. |
| `published_date`, `modified_date` | str \| null | Advisory timestamps, source precedence NVD > OSV > GCVE. |
| `withdrawn_date` | str \| null | Withdrawal timestamp (OSV only). Non-null means the advisory was retracted. |

## tables/coverage_dropped.csv

Every attempted-but-not-`done` manifest row, so the gap between the sample
and the tables is never silent. Columns: `npm_name`, `git_url`,
`snapshot_date`, `state`, `server_status`, `error`, `attempts`.

## tables/remediation_events.parquet

Produced by `run.py analyze` (mine-lag step): one row per **mining unit**,
event=1 presence intervals grouped on (project, dependency,
vulnerable-version-set, snapshot window), so CVEs fixed by the same lockfile
change are mined once. Each row records where in the repo's git history the
vulnerable resolved version left the ROOT lockfile (see the README's
mine-lag section). `stats.merge_day_resolution` joins these back onto
intervals on `(project_id, affected_dependency, last_seen)`.

| Column | Type | Meaning |
|---|---|---|
| `npm_name`, `project_id` | str | The project mined. |
| `affected_dependency` | str | The vulnerable package. |
| `affected_version` | str | Comma-joined sorted set of the vulnerable resolved versions observed at `last_seen` (all workspaces). |
| `last_seen`, `next_snapshot` | str | The window bounds as `YYYY-MM-DD`: last snapshot where the pair was present, next completed snapshot where it was gone. |
| `lockfile` | str | Root lockfile the version was last seen in (null when it never appeared in one). |
| `fix_commit_sha`, `fixed_at` | str | For `found` rows: the first commit at which no occurrence of any vulnerable version remains in the root lockfile, and its committer date. Null otherwise. |
| `fix_kind` | str | For `found` rows: how the vulnerable versions left the lockfile. `upgraded`: still resolves at non-vulnerable versions. `removed_direct`: declared in the root `package.json` at the boundary commit, no longer declared at the fix commit (deliberately dropped). `removed_transitive`: never a direct dependency at the boundary (left because a parent was upgraded). `removed`: the legacy unsplit value, direct/transitive split unknowable. `anomalous_still_present`: a vulnerable version still resolves in a lockfile outside the search set. All three `removed*` values are treated identically by every consumer. |
| `fix_to_version` | str | For `upgraded` (and `anomalous_still_present`) rows: comma-joined sorted set of versions at the fix commit. Null otherwise. |
| `method` | str | `linear_scan` (windows <= 6 commits, exact, detects reintroductions) or `binary_search` for `found`; failure reason otherwise: `no_lockfile_commits`, `not_in_root_lockfile`, `still_present_at_window_end`, `non_monotonic`, `unparseable_lockfile`, `unparseable_git_url`. |
| `status` | str | `found` (day-resolution fix located), `ambiguous` (excluded from KM by `merge_day_resolution`, but counted), `not_found` (no lockfile-touching commits in the window). |

Commit lists, parsed lockfile blobs, and per-unit results are cached under
`<study>/mining_cache/` (`results.jsonl` makes the mine resumable).

## tables/triangulation.parquet (frozen)

Independent-scanner cross-check, produced by the pre-simplification
`triangulate.py` (RESULTS.md section 13). Not produced by this tree; if a
copy exists from before the simplification, `numbers.build_numbers` folds
it into `results_numbers.json`'s `triangulation` block unchanged. See
RESULTS.md's regeneration section.

## tables/results_numbers.json

Every number RESULTS.md cites, written by `run.py analyze`
(`js_vuln_study/numbers.py`). Top-level keys:

| Key | Always present? | Content |
|---|---|---|
| `run_meta` | yes | Provenance subset: `knowledge`, `analyzer_steps`, `api_version`, `experiment_sha`, `api_sha`, `backend_sha`, `ts`. |
| `coverage` | yes | Attempted/skip-marker/state counts, `grid_len` (the number of dated snapshots in the DATA, not a hard-coded constant), `balanced_panel` (projects completing every grid date), `near_balanced`, per-date completion, failure summary. |
| `headline` | yes | `stats.headline` on the HEAD slice: prevalence, load, concentration (Gini, top packages), `pkgs_clear_50/80/90`. |
| `sweep` | yes | `stats.sensitivity_sweep`: the headline scalars under `all`/`match_correct_only`/`non_withdrawn`/`direct_only`. |
| `epss` | yes | EPSS coverage and distribution on the HEAD slice. |
| `match_flags`, `winning_source_head` | yes | Value counts of `conflict_flag`/`winning_source` at HEAD. |
| `disclosure_coverage_hist` | yes | Share of historical vuln rows with a known/future-dated publication date. |
| `survival_residence`, `survival_disclosed` | yes | `stats.km_by_severity` over all instances / the disclosed-only subset. |
| `survival_day_resolution` | if mining has run | Mined event counts, `stats.km_by_severity` with the day-resolution tail, `fix_kind` split and the upgrade-only KM. |
| `rqc` | yes | Spearman correlation of star rank vs vulnerability load. |
| `rqd` | yes | Per-package-manager project count, median dependencies, median vulnerabilities. |
| `triangulation` | if `tables/triangulation.parquet` exists | See above (frozen). |
| `trajectory_balanced`, `trajectory_balanced_meta` | yes | Balanced-panel point-in-time disclosed-vulnerability trajectory. |
| `ladder`, `drift` | if `archive/*/*.json` exists | Frozen appendix blocks, loaded verbatim (RESULTS.md sections 14, 15). |
| `cohort` | if `analyze --baseline` was passed | `numbers.compare_cohorts` output: pooled/by-severity/recency/upgrade-only/by-repo KM blocks for `baseline` and `cohort`, plus the knowledge-stamp equality check. |

`balanced_panel_18` is kept as an alias of `balanced_panel` for one release;
new code should read `balanced_panel`.
