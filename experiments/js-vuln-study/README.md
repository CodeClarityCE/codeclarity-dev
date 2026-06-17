# JS Vulnerability Experiment

Driver that scans the **top 100 GitHub projects by stars** (JavaScript +
TypeScript) that commit both a `package.json` and a lockfile, via the
CodeClarity API, and collects the results into Parquet tables for analysis.
Each project is analyzed once at its default-branch **HEAD**.

No changes to the CodeClarity codebase are required; this directory contains
only an external client and is independent of the monorepo build.

## Prerequisites

1. A running CodeClarity dev stack (`make up` from the repo root, see the
   project [CLAUDE.md](../../CLAUDE.md)).
2. Python 3.11+.
3. **Required**: a GitHub classic PAT with scope `public_repo` (or `repo`),
   exported as `GITHUB_TOKEN`. Without it the server imports projects as
   FILE-type archive uploads (awaiting a zip that never arrives) instead of
   cloning them. The same token also lifts the GitHub API rate limit on
   historical-commit lookups from 60/h to 5000/h.

## Setup

```bash
cd experiments/js-vuln-study
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env if the API is not on https://localhost/api or the default creds differ
```

## Workflow

Each command writes into `data/`, which is gitignored.

1. **Build the sample** (queries the GitHub search API):
   ```bash
   python run.py sample            # top 100 by default
   python run.py sample --limit 50
   ```
   Ranks the top-starred `language:JavaScript` and `language:TypeScript` repos,
   keeps the first `--limit` whose repository root commits both a `package.json`
   and a lockfile, and writes `data/sample.json`. Repo probes are cached in
   `data/repo_probe_cache.jsonl`; pass `--refresh` to discard the cache.

2. **Smoke test** — single project (vuejs/core) at HEAD:
   ```bash
   python run.py smoke
   ```
   Confirms auth, org/analyzer creation, import, analysis trigger, polling,
   and result persistence all work. Exits when the analysis is terminal.

3. **Submit the batch** (HEAD only by default):
   ```bash
   python run.py submit            # 100 projects, one HEAD analysis each
   python run.py submit --limit 5  # quick trial
   python run.py submit --snapshots  # also analyze historical quarterly snapshots
   ```
   Imports every project and queues one HEAD analysis (or the full historical
   grid with `--snapshots`). All submitted analyses are recorded in
   `data/manifest.jsonl`. Re-running skips (project, date) pairs already present.

4. **Poll until everything is terminal**:
   ```bash
   python run.py poll
   ```
   Safe to interrupt and resume — in-flight records keep status `submitted`;
   only terminal (`completed`, `success`, `failed`) ones have results fetched.
   Polling uses exponential backoff up to 120 s and a 30 min hard cap per
   analysis.

5. **Build the tidy tables**:
   ```bash
   python run.py collect
   ```
   Emits `data/tables/analyses.parquet`, `vulns.parquet`, `dependencies.parquet`.
   Load them straight into pandas / R:

   ```python
   import pandas as pd
   a = pd.read_parquet("data/tables/analyses.parquet")
   a[["npm_name", "total_dependencies", "total_vulnerabilities"]].sort_values(
       "total_vulnerabilities", ascending=False
   )
   ```

## Files

| Path | Purpose |
|------|---------|
| `run.py` | CLI entry point (`sample` / `smoke` / `submit` / `poll` / `collect`) |
| `js_vuln_study/client.py` | Thin CodeClarity REST wrapper with JWT refresh |
| `js_vuln_study/sample.py` | Top-N GitHub-stars sampler (filters to package.json + lockfile) |
| `js_vuln_study/snapshots.py` | Resolves the HEAD commit (and optional historical dates) via the GitHub API |
| `js_vuln_study/orchestrator.py` | Pipeline: import → submit → poll → persist raw JSON |
| `js_vuln_study/collect.py` | Raw JSON → `analyses.parquet` / `vulns.parquet` / `dependencies.parquet` |
| `data/` | Run artefacts (manifest, raw blobs, final tables) |

## Verification checklist (before the full 100-project run)

Run in order; each step gates the next.

1. `python run.py smoke` completes and writes `data/raw/<pid>/<aid>/{js-sbom,vuln-finder,license-finder}.json`.
2. `python run.py sample` writes `data/sample.json` with the requested number of
   entries — all `tier="top-100"`, recognizable high-star repos, ranks in star
   order. Spot-check a few on github.com for package.json + a lockfile.
3. `python run.py submit --limit 5 && python run.py poll` —
   five projects through the happy path.
4. Diff `data/tables/analyses.parquet` against the frontend result pages at
   <https://localhost:443> for three random rows to confirm numeric parity.
5. Spot-check one project's `total_vulnerabilities` against `npm audit`.
   Some disagreement is expected, but magnitudes should match.
