# JS Vulnerability Experiment

Measures the known-vulnerable-dependency exposure of the **top-starred GitHub
JavaScript/TypeScript projects**, cross-sectionally at HEAD and longitudinally
across quarterly snapshots (2022-Q1 – 2026-Q2), by scanning each (project,
snapshot) pair through the CodeClarity pipeline (js-sbom → vuln-finder /
license-finder). Output is a set of tidy Parquet tables — one row per scan, per
vulnerability instance, per resolved dependency — documented column-by-column
in [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

This directory is an external API client only; it requires no changes to the
CodeClarity codebase and is independent of the monorepo build.

## Prerequisites (in order)

1. **Running dev stack** — `make up` from the repo root (see the project
   [CLAUDE.md](../../CLAUDE.md) for bring-up and restart semantics).
2. **Populated knowledge DB** — vulnerability counts are meaningless against an
   empty `knowledge` database. Either build it:
   ```bash
   make knowledge-setup     # create schema
   make knowledge-update    # mirror NVD/OSV/EPSS/… (needs an NVD API key; slow)
   ```
   or restore from dumps:
   ```bash
   make download-dumps && make restore-database
   ```
   **Check before submitting anything**: `GET /knowledge/provenance`
   (authenticated) returns the last-update timestamp per source plus
   `epss_rows`. Non-null source timestamps mean the vuln data is populated;
   **non-zero `epss_rows` is required** for the `epss_score` / `epss_percentile`
   fields to be populated in the output.
   ```bash
   TOKEN=$(curl -sk https://localhost/api/auth/authenticate \
     -H 'Content-Type: application/json' \
     -d '{"email":"john.doe@codeclarity.io","password":"ThisIs4Str0ngP4ssW0rd?"}' \
     | jq -r .data.token)
   curl -sk https://localhost/api/knowledge/provenance \
     -H "Authorization: Bearer $TOKEN" | jq
   ```
3. **GitHub classic PAT** with scope `public_repo` (or `repo`), set as
   `GITHUB_TOKEN`. Required: without it the server imports projects as
   FILE-type archive uploads (awaiting a zip that never arrives) instead of
   cloning them, and GitHub API lookups are capped at 60/h instead of 5000/h.
   *Security*: put the token in `.env` (gitignored) and nowhere else; it is
   also stored server-side as the org's GitHub integration. Rotate it
   immediately if it was ever pasted into a shared terminal, log, or chat.
4. **Python 3.11+ venv**:
   ```bash
   cd experiments/js-vuln-study
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env    # then edit — see Configuration below
   ```

## Read this before comparing numbers

> **Vulnerability counts are a function of the knowledge-DB snapshot.** A scan
> run today and a scan run after the next `make knowledge-update` are counting
> against different CVE universes. Every `submit`/`smoke` invocation records
> the active snapshot (per-source timestamps + EPSS row count) in
> `data/run_meta.jsonl`; `collect` copies the latest record to
> `data/tables/run_meta.json` and **warns when the manifest mixes analyses
> submitted under differing knowledge snapshots** — such counts are not
> strictly comparable across runs.

## Sampling methodology

`run.py sample` builds the project list from the GitHub search API:

- Pulls the top-starred repos for `language:JavaScript` and
  `language:TypeScript` separately (the search API cannot OR languages):
  `stars:>1000` (`MIN_STARS`), 3 pages × 100 results (`SEARCH_PAGES`) →
  ≤ 300 candidates per language, merged and re-ranked by stars.
- Resolves each candidate's canonical slug via `GET /repos/{owner}/{repo}`
  (follows renames, so `react/react` collapses onto `facebook/react`) and
  de-duplicates on the canonical slug.
- Drops forks, archived, and disabled repos.
- Keeps repos whose **repository root commits both a `package.json` and a
  lockfile** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, or
  `npm-shrinkwrap.json`), probing in star order until `--limit` qualify.
- Optionally (`--min-npm-downloads N`) drops npm-published packages below a
  last-month download floor; unpublished apps/monorepos are kept regardless.

**Selection bias — state it in any write-up**: requiring a root lockfile
excludes popular libraries that deliberately do not commit one (express,
lodash, …) and monorepos whose packages live below the root. The sample skews
toward applications and monorepos with parseable root lockfiles; Yarn-Berry
lockfile formats additionally fail SBOM generation downstream (see the
threats-to-validity section of [RESULTS.md](RESULTS.md)). Expect some
attrition: the 2026-08 run completed 98 of 100 sampled repos at HEAD.

Repo probes are cached in `data/repo_probe_cache.jsonl` keyed by (owner, repo);
pass `--refresh` to discard the cache and re-probe.

## Snapshot grid

`js_vuln_study/snapshots.py` defines the grid: **quarterly dates from
2022-01-01 through 2026-04-01** (18 historical snapshots, 2022-Q1 – 2026-Q2)
**plus HEAD** — 19 per project with `submit --snapshots`, HEAD only by default.

- For each historical date, the latest default-branch commit at or before the
  date is resolved via the GitHub API. **Repos that do not yet exist at a date
  are skipped**, so the longitudinal panel is *unbalanced*: the set of
  projects grows over time, and naive per-snapshot means are
  composition-confounded (see the longitudinal section of RESULTS.md — use a
  balanced panel).
- **HEAD rows are pinned**: at submit time the branch tip is resolved to a
  concrete SHA and the analysis is submitted with that `commit_hash`, so the
  row is reproducible. `snapshot_date` stays `"HEAD"` as the grouping key. If
  resolution fails, the submission proceeds unpinned (branch only) with a
  warning.

## Workflow

Each command loads `.env` and writes into `data/` (gitignored). The manifest
`data/manifest.jsonl` is the **source of truth** for what has been attempted:
`submit` de-duplicates on `(git_url, snapshot_date)`, so every command is safe
to re-run and a run is resumable at any point.

1. **Build the sample**:
   ```bash
   python run.py sample                 # top 100 by default
   python run.py sample --limit 50 --refresh
   ```
   Writes `data/sample.json`.

2. **Smoke test** — single project (vuejs/core) at HEAD:
   ```bash
   python run.py smoke
   ```
   Verifies auth, org/analyzer/integration provisioning, import, analysis
   submission, polling, and result persistence end-to-end. Also records
   `run_meta.jsonl`, so a smoke run doubles as a provenance check.

3. **Submit the batch**:
   ```bash
   python run.py submit                 # one pinned-HEAD analysis per project
   python run.py submit --limit 5       # quick trial
   python run.py submit --snapshots     # full 19-snapshot historical grid
   ```
   Imports each project once (IDs reused from the manifest on re-runs) and
   POSTs one analysis per snapshot not already in the manifest. Rows that fail
   to submit are recorded as `failed-submit`; projects/snapshots dropped
   before submission (resolution or import failure) are recorded as `skipped`
   with the reason, so coverage accounting is never silent. Projects are
   processed on a thread pool (`JS_VULN_SUBMIT_WORKERS`, default 8) — snapshot
   resolution dominated the old serial submit — while manifest writes stay on
   the main thread, so row order is deterministic. Pairs on the
   unresolvable-commit denylist (below) are skipped with a `skipped` manifest
   row unless `--ignore-denylist` is passed.

4. **Poll until terminal** (then auto-retry):
   ```bash
   python run.py poll                    # converge, then up to 2 retry+poll passes
   python run.py poll --auto-retry 0     # single poll pass, no re-drives
   python run.py poll --ignore-denylist  # re-drive even denylisted pairs
   ```
   Polls all `submitted` rows with exponential backoff (10 s → 120 s),
   persists plugin results to `data/raw/{project_id}/{analysis_id}/*.json` on
   completion, and rewrites the manifest after every transition — **safe to
   interrupt and resume**. Two client-side give-up rules: a *running* analysis
   with no per-step progress for `JS_VULN_POLL_TIMEOUT` (default 20 min) is
   marked `failed`; a *queued-only* analysis older than
   `JS_VULN_STARTED_TIMEOUT` (default 24 h; 0 disables) is marked `failed`.
   **For full-grid runs raise the stall timeout** — with a thousand-deep
   download queue the server marks analyses "ongoing" long before they make
   per-step progress, and the 20-min default mass-fails work that is merely
   waiting its turn (`JS_VULN_POLL_TIMEOUT=14400 python run.py poll` worked
   well for a 1,600-analysis run).
   For sad-terminal analyses the server's `failure_reason` (or the failing
   plugin's error) is captured into the manifest `error` field. Each terminal
   analysis's downloader clone is deleted once results are persisted (see
   Troubleshooting → Disk).
   After convergence, `--auto-retry N` (default 2) re-drives the remaining
   retryable sad-terminal rows via the retry machinery and polls again, up to
   N passes or until nothing retryable remains — one command now covers the
   poll → retry → poll cycle.
   **Denylist**: `data/unresolvable_commits.jsonl` records
   `{git_url, snapshot_date, commit, reason, recorded_at}` rows for
   (project, snapshot) pairs whose download re-fails identically on every
   re-drive (the downloader's `CommitUnresolvable` failure_reason, or the
   legacy `failure at stage-0/download; no plugin result` signature — the
   ~225-pair set that repeated across full runs). `poll` appends to it
   automatically on such failures; `submit`/`retry` skip denylisted pairs,
   converting them to `skipped` manifest rows, unless `--ignore-denylist` is
   passed. Delete a line (or the file) to make a pair eligible again.

5. **Retry failures** (re-drives sad-terminal rows *in place*):
   ```bash
   python run.py retry                          # all retryable rows
   python run.py retry --dry-run                # show what would be resubmitted
   python run.py retry --status failed-submit   # only submission failures
   python run.py retry --date 2024-01-01        # one snapshot date (or HEAD)
   python run.py retry --project facebook/react # one project (npm_name)
   python run.py retry --ignore-denylist        # re-drive denylisted pairs too
   ```
   Default statuses: `cancelled`, `failed`, `failed-submit`, `failure`. Each
   selected row is resubmitted with its stored snapshot (a pinned HEAD stays
   pinned to the same commit) and **replaced** in the manifest — fresh
   `analysis_id`, status `submitted`, error cleared — never appended, so the
   `(git_url, snapshot_date)` key stays unique. The manifest is flushed after
   every replacement, so Ctrl-C never double-submits. `skipped` rows have no
   project/branch to rebuild from — re-run `submit` for those. Use it after
   fixing the underlying cause (e.g. a download timeout), then `poll` again.

6. **Build the tidy tables**:
   ```bash
   python run.py collect
   python run.py collect --no-deps     # skip the per-dependency table (longitudinal runs OOM otherwise)
   ```
   Prints a coverage report (all manifest rows bucketed — completed / failed /
   skipped / failed-submit / in-flight — summing to the attempts), writes
   `data/tables/{analyses,vulns,dependencies}.parquet`,
   `coverage_dropped.csv`, and copies the latest provenance record to
   `data/tables/run_meta.json`. Warns if the manifest mixes knowledge-DB
   snapshots. See [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

7. **Clean up** (destructive — clears the backlog):
   ```bash
   python run.py clean --dry-run        # what would be deleted
   python run.py clean                  # batch-delete all the org's projects/analyses
   python run.py clean --clones         # …and sweep the on-disk clone tree
   python run.py clean --clones-only    # sweep clones only; safe mid-run
   ```
   Also accepts `--ids`, `--limit`, `--batch-size` (API caps one batch-delete
   call at 500 ids).

## The knowledge-staleness ladder (`resubmit-frozen`)

The ladder answers "how much of the measured exposure is just the
vulnerability database's vintage?" by re-scanning the archived 2026-06 run's
**exact pinned commit SHAs** under several **dated knowledge-DB states**
(rungs: the 2026-08-03 natural dump plus reconstructed 2026-06-29, 2026-01-01,
2025-01-01, 2024-01-01, 2023-01-01 states), with the backend code held fixed —
so any result delta is 100% attributable to the knowledge state. Dated states
are restored via the root Makefile's dated knowledge-restore targets (OSV
rebuilt from the advisory-database git history, EPSS from FIRST's dated CSVs;
nvd/gcve/npm stay frozen at the natural dump).

Each rung runs in its **own data dir** via `JS_VULN_DATA_DIR` (absolute, or
relative to this directory; export it in the shell — it is read at import,
before `.env` loads). Every artifact path — manifest, `setup.json`,
`raw/`, `tables/` — derives from it, so `poll`/`collect` work per-rung
unchanged. A rung dir needs no `sample.json`: `resubmit-frozen` derives
everything from the source manifest.

Per rung, after restoring its dated knowledge state:

```bash
export JS_VULN_DATA_DIR=data-ladder/rung-<T>       # e.g. rung-2024-01-01
python run.py resubmit-frozen \
    --from data/archive-run-2026-06-snapshot/manifest.jsonl \
    --only-completed --dedupe-sha --dry-run        # preview: expect ~1,341
python run.py resubmit-frozen \
    --from data/archive-run-2026-06-snapshot/manifest.jsonl \
    --only-completed --dedupe-sha                  # submit for real
python run.py poll                                 # converge (raise JS_VULN_POLL_TIMEOUT as usual)
python run.py collect --no-deps                    # rung tables + run_meta.json
```

Semantics: the source manifest is **read-only**; `--only-completed` keeps
`completed`/`success` rows; `--dedupe-sha` collapses rows sharing
`(git_url, commit_hash)` onto the first, so a frozen tree pinned by several
snapshot dates is scanned once (1,423 completed archive rows → 1,341 trees).
Every submission is **commit-pinned at the archived SHA** — pinned-HEAD rows
included, they are never re-resolved — with `snapshot_date` carried over
verbatim, so no GitHub access is needed at all. Rows without a `commit_hash`
become `skipped` rung-manifest rows (`no pinned commit in source`). The rung's
own `(git_url, snapshot_date)` dedupe makes re-runs resumable/idempotent; the
rung's denylist (merged with the source dir's, if any) is honoured unless
`--ignore-denylist`. Projects the server no longer has (archived ids are stale
after `run.py clean`) are re-imported by `git_url`. `--dry-run` prints the
selection/dedup/skip summary and writes nothing.

Once every rung is collected, aggregate the dose-response:

```bash
python scripts/ladder_dose_response.py --rungs 'data-ladder/rung-*' \
    --archive data/archive-run-2026-06-snapshot   # default out: data/tables/ladder_dose_response.json
```

Per rung (sorted by knowledge date) it reports completed analyses, instances,
instances on the **common completed subset** (same `(git_url, commit_hash)`
keys in every rung — the like-for-like panel), severity/source mixes, and
deltas + pair-set Jaccard vs the freshest rung; it warns if `api_sha`/
`backend_sha` differ across rungs, and when a rung's knowledge date lands near
the archive's it reports rung-vs-archive agreement (reconstruction-fidelity
bound). `scripts/extract_results_numbers.py` folds the JSON in under
`ladder`, and `notebooks/analysis.py` renders the instances-vs-staleness
curve. See DATA_DICTIONARY.md for the rung-dir and output-file layouts.

## Day-resolution remediation lag (`mine-lag`)

The survival analysis (RQ-G) observes projects quarterly, so every fix is
interval-censored at ~90 days: an event=1 presence interval only says the fix
landed between `last_seen` and the next completed snapshot. `mine-lag`
recovers the day: for each event=1 interval it lists the commits touching any
root lockfile (`yarn.lock` / `package-lock.json` / `pnpm-lock.yaml` — the
js-sbom list) inside that window, then binary-searches them for the first
commit where **no occurrence** of the vulnerable resolved version remains in
the root lockfile (all-occurrences rule; small windows are scanned linearly,
which detects reintroductions exactly and marks them `ambiguous`).

```bash
python run.py mine-lag --dry-run    # unit count + projected request budget only
python run.py mine-lag --limit 5    # smoke: first 5 units (deterministic order)
python run.py mine-lag              # full mine (resumable — safe to interrupt)
```

Intervals are grouped into **mining units** on (project, dependency,
vulnerable-version-set, window) — CVEs fixed by the same lockfile change are
mined once (~7.6k units from ~16.6k event intervals). Commit lists and parsed
lockfile blobs are cached under `data/mining_cache/` and per-unit results
append to `mining_cache/results.jsonl`, so re-runs skip completed units; only
the commit-list calls count against the GitHub core-API limit (raw blob
fetches hit `GH_RAW_BASE`). Output: `data/tables/remediation_events.parquet`
(`--out` overrides; see DATA_DICTIONARY.md). `stats.merge_day_resolution`
folds the found fixes back into the intervals (`resolution='day'`, rewritten
`duration_days`; ambiguous mines excluded from KM but counted) —
`scripts/extract_results_numbers.py` reports it under
`survival_day_resolution`, and `notebooks/analysis.py` renders the
quarter-vs-day KM comparison.

## Configuration

`.env.example` is the canonical, commented reference — copy it to `.env` and
edit. Summary:

| Variable | Purpose |
|----------|---------|
| `CC_BASE_URL`, `CC_EMAIL`, `CC_PASSWORD`, `CC_VERIFY_TLS` | API endpoint + credentials. From a devcontainer/agent shell use `http://172.17.0.1:3000` (no `/api` prefix). |
| `GITHUB_TOKEN` | **Required.** Classic PAT, `public_repo`. `GH_TOKEN` is honoured as an alias for GitHub API lookups (sample / snapshot resolution) only — **the integration setup reads `GITHUB_TOKEN` exclusively**. |
| `JS_VULN_ORG_NAME`, `JS_VULN_ANALYZER_NAME` | Org / analyzer names provisioned on first run (defaults `js-vuln-study-2026` / `js-vuln-study-v2`). `data/setup.json` caches the provisioned IDs and **wins over these** — delete it to re-provision after renaming. |
| `JS_VULN_DATA_DIR` | Override the run's data dir (default `data/`; absolute, or relative to this directory). Used per-rung by the knowledge-staleness ladder. Read at import — export it in the shell, not `.env`. |
| `JS_VULN_POLL_TIMEOUT`, `JS_VULN_STARTED_TIMEOUT` | Client-side poll give-up rules, seconds (defaults 1200 / 86400; see Workflow step 4). |
| `JS_VULN_SUBMIT_WORKERS` | Project-level `submit` parallelism (default 8); manifest writes stay single-threaded. |
| `JS_VULN_CLONE_DIR` | Where the downloader's clones land on this host (default `<repo-root>/private`, correct in the devcontainer). Point at a nonexistent path to disable clone reclamation. |
| `PG_DB_HOST/PORT/USER/PASSWORD` | Direct-Postgres fallback for provenance capture, used only when the API predates `GET /knowledge/provenance`. In dev the DB port is published on the **host only**, so this fails (expectedly) from inside a container; run_meta then records nulls. |

**Server-side, not read by the harness**: `DOWNLOAD_TIMEOUT_SECONDS` bounds a
single downloader clone/resolve (default 600 s,
`backend/services/downloader/git.go`). Historical-commit analyses resolve in
two tiers — a shallow fetch-by-SHA, then a blobless-clone fallback — and
deep-history checkouts of big repos exceed the default. **Recommended: 900 for
snapshot runs.** Set it on the downloader container: add it to the
`environment:` of `service-downloader` in
`backend/services/downloader/.cloud/docker/docker-compose.yaml` (or to
`.cloud/env/.env.dev`, the env_file it loads) and restart the service.

The analyzer's plugin versions (`PLUGIN_VERSIONS` in `js_vuln_study/client.py`)
apply only to a *newly created* analyzer; `run_meta.jsonl` records the steps
the analyzer actually runs, read back from the API at submit time.

## Running against a different GitHub/npm endpoint

The GitHub and npm endpoint bases are environment-overridable: `GH_API_BASE`,
`GH_RAW_BASE`, `GH_WEB_BASE`, `NPM_REGISTRY_BASE`, `NPM_DOWNLOADS_BASE` (see
`.env.example` for defaults and per-variable roles). To repoint a run:

1. Export the variables in the environment (they are read once at module
   import, e.g. `GH_API_BASE=… python run.py sample`), with a `GITHUB_TOKEN`
   valid for that endpoint.
2. Delete `data/sample.json` and `data/repo_probe_cache.jsonl` before
   resampling — both are keyed to the previous endpoint's repositories.
3. Re-run `python run.py sample` and proceed as usual.

The sampled corpus — and therefore every downstream count — depends on the
configured endpoint's repository population: endpoints with different
populations yield different top-N samples, so results produced against
different endpoints are comparable at the corpus level only, never
project-by-project (see the threats-to-validity section of RESULTS.md).

## Outputs

`collect` emits `data/tables/`: `analyses.parquet` (one row per completed
scan), `vulns.parquet` (one row per vulnerability instance),
`dependencies.parquet` (one row per resolved dependency; optional),
`coverage_dropped.csv` (every attempted-but-dropped row), and `run_meta.json`
(the provenance record — commits, analyzer steps, knowledge-DB snapshot — so a
dataset always carries what produced it). Column-by-column reference,
including status vocabulary and semantic caveats (instances vs unique
packages, resolved multiset vs install set):
**[DATA_DICTIONARY.md](DATA_DICTIONARY.md)**.

## Troubleshooting

**Stack restarts / lost queue messages.** In dev, RabbitMQ has **no data
volume** — `make down && make up` deliberately clears the queue, so all
in-flight messages are lost while the analysis rows persist in Postgres.
Recovery is DB-driven: the dispatcher's reaper runs a startup recovery pass
(re-driving every non-terminal analysis; pre-download ones by re-running the
downloader, later stages in place) plus a periodic pass. Genuine download
failures are marked `failure` (not re-driven), and non-terminal analyses older
than `RECOVERY_MAX_AGE` (default 24 h) are retired as `failure`. Practically:
after a restart, just run `python run.py poll` again — the backend re-drives
orphans on its own.

**Stuck analyses.**
- RabbitMQ management UI: <http://localhost:15672> (guest/guest). A
  `dispatcher_<plugin>` queue with `consumers=0` means that plugin's consumer
  crashed and is stalling analyses — restart it.
- Downloader logs (`make logs`, or the service's container) show clone/timeout
  errors. On download failures the downloader writes the analysis
  `failure_reason`, which `poll` surfaces into the manifest `error` field and
  `collect` into `coverage_dropped.csv` — check there first.
- `updating_db` is a non-terminal status: the analysis resumes once the
  knowledge-DB refresh notifies the dispatcher.

**Disk.** The downloader clones every analysed snapshot under
`<repo-root>/private/{org}/projects/{project}/{commit|branch}` and the backend
never deletes those trees. `poll` reclaims each checkout as soon as its
analysis is terminal and results are persisted; `python run.py clean
--clones-only` sweeps leftovers mid-run without touching the backlog (add
`--dry-run` first). Set `JS_VULN_CLONE_DIR` to relocate — or point it at a
nonexistent path to keep checkouts for inspecting failures by hand.

## Files

| Path | Purpose |
|------|---------|
| `run.py` | CLI entry point (`sample` / `smoke` / `submit` / `poll` / `retry` / `collect` / `triangulate` / `resubmit-frozen` / `mine-lag` / `clean`) |
| `scripts/ladder_dose_response.py` | Aggregates per-rung tables into the knowledge-staleness dose-response JSON |
| `js_vuln_study/client.py` | Thin CodeClarity REST wrapper with JWT refresh; `PLUGIN_VERSIONS` |
| `js_vuln_study/sample.py` | Top-N GitHub-stars sampler (package.json + lockfile filter, canonical-slug dedup) |
| `js_vuln_study/snapshots.py` | Snapshot grid + commit resolution (historical dates, pinned HEAD) |
| `js_vuln_study/orchestrator.py` | Pipeline: import → submit → poll → persist raw JSON; retry |
| `js_vuln_study/collect.py` | Raw JSON → Parquet tables + coverage report |
| `js_vuln_study/provenance.py` | Per-run provenance capture → `data/run_meta.jsonl` |
| `js_vuln_study/reclaim.py` | Deletes the downloader's clones once their analysis is terminal |
| `js_vuln_study/lockfiles.py` | Minimal root-lockfile parsers (npm v1-v3, yarn v1/berry, pnpm both dialects) |
| `js_vuln_study/remediation.py` | Day-resolution fix-commit miner (`mine-lag`) over the repos' lockfile history |
| `tests/` | Unit tests (`.venv/bin/python -m pytest tests/ -q`) |
| `notebooks/` | Analysis notebook + PDF report (see `notebooks/README.md`) |
| `DATA_DICTIONARY.md` | Column-by-column reference for every output file |
| `RESULTS.md` | Canonical results document: provenance, coverage, findings, threats to validity |
| `data/` | Run artifacts (manifest, run_meta, raw blobs, tables) — gitignored |

## Verification checklist (before a full run)

Run in order; each step gates the next.

1. `GET /knowledge/provenance` shows non-null source timestamps and
   `epss_rows > 0` (see Prerequisites).
2. `python run.py smoke` completes and writes
   `data/raw/<pid>/<aid>/{js-sbom,vuln-finder,license-finder}.json`, and
   `data/run_meta.jsonl` gains a record with non-null `knowledge_sources`.
3. `python run.py sample` writes `data/sample.json` with the requested count —
   recognizable high-star canonical repos, ranks in star order, no forks.
   Spot-check a few on github.com for a root package.json + lockfile.
4. `python run.py submit --limit 5 && python run.py poll` — five projects
   through the happy path; check `epss_score` is populated for CVE rows after
   a trial `collect`.
5. Diff `data/tables/analyses.parquet` against the frontend result pages at
   <https://localhost:443> for three random rows to confirm numeric parity.
6. Spot-check one project's `total_vulnerabilities` against `npm audit`.
   Some disagreement is expected (different scanners), but magnitudes should
   match.
