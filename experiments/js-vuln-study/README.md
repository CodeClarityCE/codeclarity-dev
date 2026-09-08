# JS Vulnerability Experiment

Measures the known-vulnerable-dependency exposure of popular JavaScript/
TypeScript projects, cross-sectionally at HEAD and longitudinally across
quarterly/monthly snapshots, by scanning each (project, snapshot) pair
through the CodeClarity pipeline (js-sbom -> vuln-finder / license-finder).
Output is a set of tidy Parquet tables, documented column-by-column in
[DATA_DICTIONARY.md](DATA_DICTIONARY.md).

This directory is an external API client only; it requires no changes to the
CodeClarity codebase and is independent of the monorepo build.

## What a study is

A **study** is a directory under `studies/` (e.g. `studies/top100`) holding
a committed `study.toml` (grid, knowledge cutoff, org/analyzer names,
retries) and a committed `sample.json` (the project list). Everything else
the study produces (`manifest.jsonl`, `raw/`, `tables/`, `report/`,
`mining_cache/`) is generated and gitignored. Two studies ship in this
repo: `studies/top100` (the canonical population) and `studies/passbolt`
(a 3-repo cohort compared against it in RESULTS.md section 16).

A second cohort, or a knowledge-staleness ladder rung, is just another
study directory: create one with its own `study.toml`, either with a
`sample` (a fresh corpus) or with `frozen_from` pointing at another study's
`manifest.jsonl` (re-scans that study's exact commit-pinned trees under a
different `knowledge_asof`, without touching GitHub).

## Prerequisites (in order)

1. **Running dev stack**: `make up` from the repo root (see the project
   [CLAUDE.md](../../CLAUDE.md) for bring-up and restart semantics).
2. **Populated knowledge DB**: vulnerability counts are meaningless against
   an empty `knowledge` database. Either build it (`make knowledge-setup &&
   make knowledge-update`, needs an NVD API key, slow) or restore from dumps
   (`make download-dumps && make restore-database`). Check before submitting
   anything:
   ```bash
   TOKEN=$(curl -sk https://localhost/api/auth/authenticate \
     -H 'Content-Type: application/json' \
     -d '{"email":"john.doe@codeclarity.io","password":"ThisIs4Str0ngP4ssW0rd?"}' \
     | jq -r .data.token)
   curl -sk https://localhost/api/knowledge/provenance \
     -H "Authorization: Bearer $TOKEN" | jq
   ```
   Non-null source timestamps mean the vuln data is populated; non-zero
   `epss_rows` is required for `epss_score`/`epss_percentile` to be populated.
3. **GitHub classic PAT** with scope `public_repo` (or `repo`), set as
   `GITHUB_TOKEN` in `.env`. Required: without it the server imports
   projects as FILE-type archive uploads instead of cloning them, and
   GitHub API lookups are capped at 60/h instead of 5000/h. Rotate it
   immediately if it was ever pasted into a shared terminal, log, or chat.
   The bundled sandbox token expires 2026-10-29 (check it rather than
   trusting this line: `curl -sI -H "Authorization: Bearer $GITHUB_TOKEN"
   https://api.github.com/rate_limit | grep -i token-expiration`). A full
   top-100 run takes hours and thousands of commit lookups, so a token that
   expires mid-run turns into skipped rows, not a clean failure.
4. **Python 3.11+ venv**:
   ```bash
   cd experiments/js-vuln-study
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env    # then edit
   ```

## Commands

```bash
python run.py sample  STUDY [--limit 100]
python run.py run     STUDY [--limit N] [--refresh-head] [--retry SLUG[@DATE] [--force]] [--dry-run]
python run.py analyze STUDY [--baseline OTHER_STUDY] [--no-mine]
python run.py clean   STUDY [--dry-run]
```

- **`sample`**: builds a fresh top-N GitHub-stars corpus and writes
  `STUDY/sample.json`. Rarely run: the canonical `sample.json` for an
  existing study is committed, and RESULTS.md's sample-identity claim
  depends on it never being regenerated for that study.
- **`run`**: provisions the org/analyzer/GitHub-integration by name, submits
  every `(git_url, snapshot_date)` key the sample (or `frozen_from`) implies
  and the manifest doesn't already have, polls to a terminal state, retries
  eligible failures, then collects the parquet tables. Resumable and
  idempotent: interrupt it (Ctrl-C, a `make down && make up`) and re-run the
  same command; a fully-covered study makes zero GitHub calls on resume.
  `--refresh-head` re-pins every HEAD row to today's tip in place, then
  stops (used to put two cohorts' HEAD scans on the same day). `--retry
  SLUG[@DATE]` re-drives one specific failed row, ignoring the retry policy
  with `--force`.
- **`analyze`**: collects (if not already done), mines day-resolution fix
  commits (resumable; skip with `--no-mine`), extracts every number
  RESULTS.md cites into `tables/results_numbers.json`, and renders the
  2-page brief PDF. `--baseline OTHER_STUDY` adds a cohort-comparison block
  and figure.
- **`clean`**: batch-deletes the study's projects (the API cancels
  in-flight analyses and removes the clone tree itself) and archives the
  manifest, so a later `run` re-imports fresh project ids instead of
  POSTing at deleted ones.

## Configuration

Two layers, each with one job:

- **`.env`** (gitignored): secrets and the API endpoint. Four keys:
  `CC_BASE_URL`, `CC_EMAIL`, `CC_PASSWORD`, `GITHUB_TOKEN`. See
  `.env.example`.
- **`<study>/study.toml`** (committed): everything about the study itself.
  See `studies/top100/study.toml` for the full key reference with comments.
  Keys: `study.name`, `study.sample`, `study.frozen_from`,
  `study.snapshots`, `study.knowledge_asof`, `study.retries`,
  `grid.quarterly`/`grid.monthly` (two inclusive date ranges expanded into
  the snapshot grid), `codeclarity.org`/`analyzer`/`plugins`/`clone_dir`,
  `analyze.recency_cutoff`/`triangulate`.

Everything else (poll backoff timing, HTTP timeouts, the miner's
`LINEAR_SCAN_MAX`, the lockfile name lists) is a code constant, documented
next to its definition.

## Sampling methodology

`run.py sample` builds the project list from the GitHub search API: pulls
the top-starred repos for `language:JavaScript` and `language:TypeScript`
separately (the search API cannot OR languages), 3 pages x 100 results each,
merges and re-ranks by stars, resolves each candidate's canonical slug via
`GET /repos/{owner}/{repo}` (follows renames), drops forks/archived/
disabled, and keeps repos whose repository root commits both a
`package.json` and a lockfile (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, or `npm-shrinkwrap.json`), probing in star order until
`--limit` qualify.

**Selection bias, state it in any write-up**: requiring a root lockfile
excludes popular libraries that deliberately do not commit one, and
monorepos whose packages live below the root. Yarn-Berry lockfile formats
additionally sometimes fail SBOM generation downstream (see the
threats-to-validity section of [RESULTS.md](RESULTS.md)).

## Snapshot grid

`study.toml`'s `[grid]` table defines two inclusive date ranges (quarterly,
monthly) expanded by `config.expand_grid()` into the full list; the default
reproduces the canonical 40-date grid (8 quarterly dates 2022-2023, then 32
monthly dates 2024-01 through 2026-08). For each historical date, the latest
default-branch commit at or before the date is resolved via the GitHub API;
repos that do not yet exist at a date are skipped, so the longitudinal panel
is *unbalanced* (the set of projects completing every date grows over time;
use the balanced panel reported in `results_numbers.json` for cross-time
comparisons). HEAD rows are pinned: at submit time the branch tip is
resolved to a concrete SHA, so the row is reproducible; `snapshot_date`
stays `"HEAD"` as the grouping key. A HEAD row whose resolution fails is
recorded as a single skipped row (not a project-wide skip); its dated
snapshots still submit normally.

## Day-resolution remediation lag (mine-lag)

The survival analysis observes projects at the study's grid resolution, so
every fix is interval-censored: an event=1 presence interval only says the
fix landed between `last_seen` and the next completed snapshot. `analyze`'s
miner recovers the day: for each event=1 interval it lists the commits
touching any root lockfile inside that window, then linearly scans (windows
of 6 commits or fewer) or bisects (larger windows) for the first commit
where no occurrence of the vulnerable resolved version remains in the root
lockfile. Results are cached under `<study>/mining_cache/` and resumable.

## Knowledge-staleness ladder and cohort comparisons

A ladder rung or a new cohort is a study directory with `frozen_from`
pointing at a source study's `manifest.jsonl`:

```toml
[study]
frozen_from = "../top100/manifest.jsonl"
knowledge_asof = "2024-01-01"
```

`run.py run studies/rung-2024-01-01` then submits every `done` row from the
source manifest, commit-pinned at its archived SHA, deduped by
`(git_url, commit_hash)` so an identical tree pinned by several snapshot
dates is scanned once, never re-resolved through GitHub. `knowledge_asof`
rides in the per-analysis vuln-finder config, so the plugin filters the
current knowledge DB to that date at match time.

RESULTS.md sections 13 (independent-scanner triangulation), 14 (the
knowledge-staleness ladder) and 15 (a June-to-August drift decomposition)
were produced by a since-simplified tooling generation and are retained as
frozen prose (plus committed JSON under `archive/`, where recoverable). The
mechanisms they used (`frozen_from`, `knowledge_asof`) survive; the
aggregation scripts that built those specific tables do not. See
RESULTS.md's regeneration section for exactly what is and isn't
reproducible from this tree.

## Outputs

`analyze` writes `<study>/tables/`: `analyses.parquet` (one row per
completed scan), `vulns.parquet` (one row per vulnerability instance),
`coverage_dropped.csv` (every attempted-but-not-done row),
`remediation_events.parquet` (mine-lag output, when mining has run),
`run_meta.json` (the provenance record) and `results_numbers.json` (every
number RESULTS.md cites). It also renders `<study>/report/brief.pdf` and
its figures under `report/figs/`. Column-by-column reference, including the
manifest's status vocabulary and every table's semantic caveats:
[DATA_DICTIONARY.md](DATA_DICTIONARY.md).

## Troubleshooting

**Stack restarts / lost queue messages.** In dev, RabbitMQ has no data
volume: `make down && make up` deliberately clears the queue, so all
in-flight messages are lost while the analysis rows persist in Postgres.
Recovery is DB-driven (see the root [CLAUDE.md](../../CLAUDE.md)'s restart
semantics section). `run.py run`'s poll loop catches transport errors and
keeps waiting, so a restart mid-poll does not crash the command: just let it
keep running, or Ctrl-C and re-run.

**Stuck analyses.** RabbitMQ management UI: <http://localhost:15672>
(guest/guest). A `dispatcher_<plugin>` queue with `consumers=0` means that
plugin's consumer crashed and is stalling analyses; restart it. `run.py run`
logs a warning after 45 minutes with no transitions across the whole poll
batch, naming this as the likely cause. `updating_db` is the one non-terminal
status the server's reaper never retires; poll's one client-side ceiling
(`--give-up-hours`, default 30h) exists specifically for it.

**Disk.** The downloader clones every analysed snapshot under
`<repo-root>/private/{org}/projects/{project}/{commit|branch}` and the
backend does not delete these mid-run; `run.py clean STUDY` (which
batch-deletes the study's projects) removes them server-side. There is no
per-poll reclamation in this harness; for a full 40-date grid, budget disk
headroom or run `--limit` in batches and `clean` between them.

## Files

| Path | Purpose |
|------|---------|
| `run.py` | CLI entry point (`sample` / `run` / `analyze` / `clean`) |
| `js_vuln_study/config.py` | `Settings` (secrets) and `Study` (study.toml) |
| `js_vuln_study/github.py` | GitHub HTTP client, backoff, repo/commit lookups |
| `js_vuln_study/client.py` | CodeClarity REST client |
| `js_vuln_study/manifest.py` | Manifest row model, status normalization, atomic I/O |
| `js_vuln_study/pipeline.py` | The state machine: provision, submit, poll, retry, clean, provenance |
| `js_vuln_study/sample.py` | Top-N GitHub-stars sampler |
| `js_vuln_study/collect.py` | Raw JSON -> Parquet tables + coverage report |
| `js_vuln_study/lockfiles.py` | Minimal root-lockfile parsers (npm v1-v3, yarn v1/berry, pnpm) |
| `js_vuln_study/miner.py` | Day-resolution fix-commit miner (`analyze`'s mining step) |
| `js_vuln_study/stats.py` | Shared statistics: gini, headline, presence intervals, KM |
| `js_vuln_study/numbers.py` | Every number RESULTS.md cites + the cohort comparison |
| `js_vuln_study/brief.py` | The 2-page shareable brief PDF |
| `tests/` | Unit tests (`.venv/bin/python -m pytest tests/ -q`) |
| `DATA_DICTIONARY.md` | Column-by-column reference for every output file |
| `RESULTS.md` | Canonical results document: provenance, coverage, findings, threats to validity |
| `studies/` | Study directories (committed `study.toml` + `sample.json`; generated state gitignored) |

## Verification checklist (before a full run)

1. `GET /knowledge/provenance` shows non-null source timestamps and
   `epss_rows > 0`.
2. `python run.py run studies/top100 --limit 2` completes and writes
   `studies/top100/raw/<pid>/<aid>/{js-sbom,vuln-finder}.json`, and
   `studies/top100/run_meta.jsonl` gains a record with non-null
   `knowledge_sources`.
3. `python run.py analyze studies/top100` writes
   `studies/top100/tables/results_numbers.json` and
   `studies/top100/report/brief.pdf`.
4. Diff `studies/top100/tables/analyses.parquet` against the frontend
   result pages at <https://localhost:443> for the two scanned projects to
   confirm numeric parity.
