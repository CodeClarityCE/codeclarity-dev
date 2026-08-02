# Data dictionary

Column-by-column reference for every artifact the harness writes. Producers:
`run.py submit`/`poll` maintain `data/manifest.jsonl` and `data/run_meta.jsonl`;
`run.py collect` derives everything under `data/tables/` from them plus the raw
plugin blobs in `data/raw/`.

Read the semantic notes, not just the column names — several fields are easy
to misread (instances vs unique packages, resolved multiset vs install set,
heuristic flags).

## data/manifest.jsonl

One JSON line per attempted `(project, snapshot)` pair — the run's source of
truth. Rows are appended by `submit`, updated in place by `poll` and `retry`
(atomic rewrite). Fields mirror `AnalysisRecord` in
`js_vuln_study/orchestrator.py`.

| Field | Type | Meaning |
|-------|------|---------|
| `npm_name` | str | Canonical `owner/repo` slug — the CodeClarity project name and the join key used across all tables. (Historical name; it is *not* an npm package name.) |
| `tier` | str | Constant `"top-100"` (kept for downstream compatibility). |
| `rank` | int | 0-based star rank within the sample (0 = most-starred). |
| `git_url` | str | Canonical GitHub URL; half of the `(git_url, snapshot_date)` dedup key. |
| `branch` | str \| null | Default branch the analysis was submitted on. Null for `skipped` rows. |
| `snapshot_date` | str | `"YYYY-MM-DD"` grid date, `"HEAD"`, or `"*"` — the sentinel for project-wide `skipped` rows recorded before any snapshot was known. |
| `commit_hash` | str \| null | The exact commit analysed. **`"HEAD"` rows carry the branch-tip SHA pinned at submit time**; null only for unpinned fallback submissions (HEAD resolution failed) and `skipped` rows. |
| `committed_at` | str \| null | ISO commit timestamp of `commit_hash`, when known. |
| `project_id` | str \| null | CodeClarity project UUID. Null for drops recorded before import (`skipped`). |
| `analysis_id` | str \| null | CodeClarity analysis UUID. Null for `skipped` and `failed-submit` rows. |
| `status` | str | See vocabulary below. |
| `error` | str \| null | Failure detail for sad rows: the server's `failure_reason` (written by the downloader on unresolvable commits / download errors), a plugin `public_error`, a client-side timeout verdict, or the skip reason. |

### Status vocabulary

| Status | Terminal? | Meaning |
|--------|-----------|---------|
| `submitted` | no | Analysis POSTed and in flight; `poll` drives it. |
| `completed`, `success` | yes (happy) | Server finished successfully; results persisted under `data/raw/{project_id}/{analysis_id}/`. Only these rows feed the Parquet tables. |
| `failure` | yes (sad) | Server-side terminal failure (e.g. download failure, plugin error). |
| `failed` | yes (sad) | Server-side terminal `failed`, **or** a client-side give-up: `error` distinguishes (`ongoing stall: …`, `queued > started ceiling`, `poll error past started ceiling`). |
| `cancelled` | yes (sad) | Cancelled server-side (e.g. by `clean`'s batch delete). |
| `failed-submit` | yes (sad) | The analysis POST itself failed; no `analysis_id` exists. |
| `skipped` | yes (sad) | Dropped before submission: snapshot-resolution failure, import failure, or no default branch. `snapshot_date` is `"*"` for project-wide drops. |

`retry` re-drives `failure` / `failed` / `cancelled` / `failed-submit` rows in
place; `skipped` rows must go through `submit` again.

## data/run_meta.jsonl and data/tables/run_meta.json

One JSON line appended per `submit`/`smoke` invocation
(`js_vuln_study/provenance.py`); `collect` copies the **latest** record to
`data/tables/run_meta.json` so a dataset always carries its provenance, and
warns when records disagree on the knowledge-DB snapshot.

| Field | Type | Meaning |
|-------|------|---------|
| `ts` | str | ISO UTC timestamp of the invocation. |
| `run_id` | str | Random UUID per invocation. |
| `experiment_sha` | str \| null | Monorepo HEAD commit at run time. |
| `experiment_dirty` | bool \| null | Whether the monorepo working tree had uncommitted changes. |
| `api_sha`, `backend_sha` | str \| null | HEAD commits of the `api/` and `backend/` submodules. |
| `api_version` | str \| null | `api/package.json` version. |
| `org_id`, `analyzer_id` | str | The org/analyzer the run used. |
| `analyzer_steps` | list \| null | The analyzer's *actual* `[[{name, version}], …]` stages, read back from the API — not the versions the client asked for. |
| `knowledge.knowledge_sources` | dict \| null | Last-update ISO timestamp per knowledge source (null = never updated). **This is the vulnerability-data snapshot the run's counts depend on.** |
| `knowledge.epss_rows` | int \| null | Row count of the EPSS table at run time. 0 means `epss_score`/`epss_percentile` will be empty. |
| `config.snapshot_dates` | list | The historical grid in effect (`snapshots.SNAPSHOT_DATES`). |
| `config.poll_timeout`, `config.started_timeout` | int | Client poll give-up rules in effect (seconds). |
| `cmd` | str | `"submit"` or `"smoke"`. |
| `sample_limit`, `snapshots` | int \| null, bool | `submit` only: the `--limit` and `--snapshots` flags used. |

Every probe is best-effort — missing git, an older API, unreachable Postgres —
so any field may be null (with a logged warning) rather than failing the run.

## data/tables/analyses.parquet

One row per **completed** `(project, snapshot)` scan (manifest status
`completed`/`success` with persisted blobs). Failed/skipped attempts are *not*
here — see `coverage_dropped.csv`.

| Column | Type | Meaning |
|--------|------|---------|
| `analysis_id`, `project_id` | str | CodeClarity UUIDs; join keys to `vulns`/`dependencies`. |
| `npm_name`, `tier`, `rank`, `git_url` | | Copied from the manifest (see above). |
| `snapshot_date` | str | Grid date or `"HEAD"`. HEAD rows carry the pinned `commit_hash`. |
| `commit_hash`, `committed_at` | str \| null | Exact commit analysed and its timestamp. |
| `total_dependencies` | int | Size of the **resolved dependency multiset**: every (workspace, package, version) entry in the SBOM. **NOT the active install set** — a version that appears in the lockfile universe but is not installed still counts, and many entries carry neither the direct nor the transitive flag. Use as a bloat proxy only. |
| `direct_dependencies`, `transitive_dependencies` | int | Multiset entries flagged `Direct` / `Transitive` by js-sbom. Not mutually exclusive with each other or exhaustive of `total_dependencies`. |
| `dev_dependencies`, `prod_dependencies` | int | Multiset entries flagged `Dev` / `Prod`. |
| `package_manager` | str \| null | Detected by js-sbom (`NPM` / `PNPM` / `YARN`), from the lockfile present. |
| `total_vulnerabilities` | int | **Vulnerability *instances***: one per (vulnerability id × affected dependency × workspace) finding reported by vuln-finder. The same CVE hitting two packages — or the same package in two workspaces — counts twice. Equals this analysis's row count in `vulns.parquet`. |
| `vulnerable_dependencies` | int | Number of **unique affected package names** — the deduplicated counterpart of `total_vulnerabilities`. |
| `direct_vulnerabilities`, `transitive_vulnerabilities` | int | Instances split by the `direct_dependency` flag (see `vulns.parquet` caveat). Sum to `total_vulnerabilities`. |
| `n_critical`, `n_high`, `n_medium`, `n_low`, `n_none` | int | Instances per CVSS severity class. Sum to `total_vulnerabilities` when every instance has a class. |

## data/tables/vulns.parquet

One row per **vulnerability instance**: a (vulnerability id × affected
dependency × workspace) tuple within one analysis. A project scanned at 19
snapshots contributes up to 19 rows for a single persistent CVE — filter on
`snapshot_date` before any cross-sectional statistic.

| Column | Type | Meaning |
|--------|------|---------|
| `analysis_id` … `committed_at` | | The same nine manifest-derived columns as `analyses.parquet`. |
| `workspace` | str | SBOM workspace the finding belongs to (`.` for single-package repos). |
| `vulnerability_id` | str | Advisory id — usually `CVE-…`, sometimes `GHSA-…`/OSV-native. |
| `affected_dependency` | str | Package name the advisory matched. |
| `affected_version` | str | Resolved version of that package in this scan. |
| `severity_class` | str \| null | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE` (CVSS class chosen by vuln-finder's severity stage). |
| `severity_score` | float \| null | CVSS base score. |
| `severity_vector` | str \| null | CVSS vector string. |
| `impact`, `exploitability` | float \| null | CVSS sub-scores. |
| `epss_score`, `epss_percentile` | float \| null | Exploit-prediction score/percentile, attached by vuln-finder from the knowledge DB's **EPSS table as of analysis time** (batched lookup by CVE id). Empty for analyses run before EPSS attachment landed (or against an unpopulated EPSS table — check `epss_rows` in `run_meta.json`), and for non-CVE ids, which have no EPSS row. |
| `conflict_flag` | str \| null | Cross-source match confidence: `MATCH_CORRECT`, `MATCH_INCORRECT`, `MATCH_POSSIBLE_INCORRECT`, `NO_CONFLICT`. ~18% of matches in the 2026-06 run were `MATCH_POSSIBLE_INCORRECT`; sensitivity analyses restrict to `MATCH_CORRECT`. |
| `winning_source` | str \| null | Which source's record won conflict resolution: `NVD`, `OSV`, `GCVE`, or `NONE`. |
| `direct_dependency` | bool | **Heuristic flag from the SBOM** — whether the affected package is declared as a direct dependency. Not a precise install-tree measure; report descriptively only. |
| `published_date`, `modified_date` | str \| null | Advisory publication / last-modified timestamps from the matched knowledge-DB record, with source precedence **NVD > OSV > GCVE**. |
| `withdrawn_date` | str \| null | Withdrawal timestamp (OSV is the only source that carries it). Non-null means the advisory was retracted — consider excluding in sensitivity checks. |

## data/tables/dependencies.parquet

One row per entry of the **resolved dependency multiset**: a (workspace,
package, version) tuple per analysis. Omitted when `collect --no-deps` is used
(longitudinal runs; the per-analysis counts in `analyses.parquet` remain).

| Column | Type | Meaning |
|--------|------|---------|
| `analysis_id` … `committed_at` | | The same nine manifest-derived columns as `analyses.parquet`. |
| `workspace` | str | SBOM workspace. |
| `name`, `version` | str | Package name and resolved version. |
| `package_manager` | str \| null | Same per-analysis value as `analyses.parquet`. |
| `direct`, `transitive` | bool | js-sbom flags. Most rows are flagged **neither** — the multiset covers the whole resolved lockfile universe, not the install tree. |
| `dev`, `prod`, `optional`, `bundled` | bool | js-sbom dependency-kind flags. |
| `licenses` | list[str] | SPDX ids attached by js-sbom (license-finder results are not folded in here). |

## data/tables/coverage_dropped.csv

Every attempted-but-dropped manifest row (`skipped`, `failed-submit`,
`failure`, `failed`, `cancelled`), so the gap between the sample and the
tables is never silent. **Columns = the manifest fields** (see above).
`skipped`/`failed-submit` rows are de-duplicated by
`(git_url, snapshot_date, status)` because resumed `submit` runs can re-log
the same transient drop. The `error` column carries the concrete reason —
including the server's `failure_reason` for download failures.

## data/tables/triangulation.parquet (planned)

Not yet produced. Planned multi-scanner triangulation table (CodeClarity vs
`npm audit` / OSV-Scanner on a subsample) to bound single-scanner error —
see FINDINGS.md §11. Schema will be documented here when it lands.
