# JS Vulnerability-Evolution Experiment

Driver for the scientific experiment described in
`/home/vscode/.claude/plans/i-want-to-write-vectorized-crab.md`: scan a
popularity-stratified sample of JavaScript projects across several historical
snapshots via the CodeClarity API and collect the results into Parquet tables
for analysis.

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

1. **Build the sample** (hits the public npms.io search API, ~2 min):
   ```bash
   python run.py sample --per-tier 100
   ```
   Writes `data/sample.json` with ~400 project specs (top-100, top-1k,
   top-10k, long-tail).

2. **Smoke test** — single project (expressjs/express) at HEAD:
   ```bash
   python run.py smoke
   ```
   Confirms auth, org/analyzer creation, import, analysis trigger, polling,
   and result persistence all work. Exits when the analysis is terminal.

3. **Submit the full batch**:
   ```bash
   python run.py submit           # 400 projects × 7 snapshots
   python run.py submit --limit 10 --head-only   # quick trial
   ```
   Imports every project and queues one analysis per target snapshot. All
   submitted analyses are recorded in `data/manifest.jsonl`. Re-running skips
   (project, date) pairs already present in the manifest.

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
   Load them straight into pandas / R to chase the six discoveries listed in
   the plan:

   ```python
   import pandas as pd
   a = pd.read_parquet("data/tables/analyses.parquet")
   a.groupby("tier")[["total_vulnerabilities","patch_none","patch_full"]].mean()
   ```

## Files

| Path | Purpose |
|------|---------|
| `run.py` | CLI entry point (`sample` / `smoke` / `submit` / `poll` / `collect`) |
| `js_vuln_study/client.py` | Thin CodeClarity REST wrapper with JWT refresh |
| `js_vuln_study/sample.py` | npms.io popularity-stratified sampler |
| `js_vuln_study/snapshots.py` | Resolves commit hashes at target dates via the GitHub API |
| `js_vuln_study/orchestrator.py` | Pipeline: import → submit → poll → persist raw JSON |
| `js_vuln_study/collect.py` | Raw JSON → `analyses.parquet` / `vulns.parquet` / `dependencies.parquet` |
| `data/` | Run artefacts (manifest, raw blobs, final tables) |

## Verification checklist (before scaling to 400 × 7)

Mirrors the plan's Verification section. Run in order; each step gates the
next.

1. `python run.py smoke` completes and writes `data/raw/<pid>/<aid>/{js-sbom,vuln-finder,license-finder,js-patching}.json`.
2. Manually feed a lockfile-less repo (e.g. a plain static-site repo) into
   `import_and_schedule` and confirm it lands in `failed`, not `submitted`
   forever.
3. `python run.py submit --limit 5 --head-only && python run.py poll` —
   five projects through the happy path.
4. Diff `data/tables/analyses.parquet` against the frontend result pages at
   <https://localhost:443> for three random rows to confirm numeric parity.
5. Spot-check one project's `total_vulnerabilities` against `npm audit`.
   Disagreement is expected (RQ5) but magnitudes should match.
