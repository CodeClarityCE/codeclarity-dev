# Results

Article-plan outline for the JS/TS dependency-vulnerability measurement
study: the sections and headline claims a resulting paper would contain,
not an exhaustive results dump. Every number below is taken from
`studies/top100/tables/results_numbers.json` (generated from the Parquet
tables by `js_vuln_study/numbers.py`) or `studies/top100/tables/run_meta.json`.
Metric definitions are in [DATA_DICTIONARY.md](DATA_DICTIONARY.md); full
methodology and reproduction commands are in [README.md](README.md). This
document covers the **top100 study only**. The Passbolt cohort comparison
is reported in the accompanying brief (`studies/passbolt/report/brief.pdf`),
not here.

## 1. Abstract

We scanned 98 of the top 100 most-starred JavaScript/TypeScript repositories
reachable through this environment's GitHub endpoint (root `package.json` +
lockfile required) at a pinned HEAD commit and across a 40-date grid
(quarterly 2022–2023, monthly 2024–2026) via the CodeClarity pipeline
(js-sbom, vuln-finder, license-finder). Three findings anchor the article:

- **Fix speed does not track severity.** Among disclosed vulnerabilities
  with an exactly-dated fix (day-resolution lockfile-history mining, 84.7%
  yield), median time-to-fix is MEDIUM 150 days, HIGH 160, LOW 204, and
  **CRITICAL slowest at 216**, not fastest. A fast minority is hidden
  inside those medians: about 15% of dated fixes land within a week, 61%
  within a quarter. Classifying every dated fix shows 68.0% are genuine
  upgrades and 31.9% are dependency removals; removals resolve faster, so
  pooling the two compresses the apparent severity gradient. Restricted to
  upgrades only, the CRITICAL-to-LOW spread widens from 394–703 days to
  467–1,067.
- **Exposure is concentrated in a handful of packages.** Just 10 of 277
  vulnerable packages account for 50% of all 16,304 vulnerability instances
  across the corpus (Gini 0.833 by package).
- **Popularity does not predict security.** Across 97 projects, the
  Spearman correlation between star rank and vulnerability load is
  statistically indistinguishable from zero (rho = 0.015, p = 0.88).

87 of 98 scanned projects (88.8%) currently ship at least one
known-vulnerable dependency. All counts are conditional on this corpus and
knowledge-database snapshot (§5).

## 2. Introduction & Research Questions

This study asks how exposed popular JavaScript/TypeScript projects are to
known-vulnerable dependencies, and how that exposure behaves over time and
across projects. Five research questions organize the analysis:

- **RQ1: Prevalence & concentration.** How many projects ship a
  known-vulnerable dependency, and how concentrated is that exposure across
  packages?
- **RQ2: Fix speed.** How long do vulnerable dependencies persist before
  remediation, and does severity predict how fast they're fixed?
- **RQ3: Popularity vs. exposure.** Does a project's popularity (star
  rank) predict its vulnerability load?
- **RQ4: Package manager.** Does the package manager in use correlate
  with vulnerability exposure?
- **RQ5: Longitudinal trend.** How has exposure evolved across the corpus
  from 2022 to 2026?

RQ2 is the study's most novel contribution: presence/absence at snapshot
resolution alone cannot show *how* a vulnerability was resolved or *how
fast*. Day-resolution fix-commit mining and a fix-mechanism classification
(upgrade vs. removal) together reveal the fast-responder tail and the
severity pattern reported in §4.1.

## 3. Methods

### 3.1 Corpus & sampling

- Repositories are ranked by star count via the environment's GitHub search
  API (`language:JavaScript` and `language:TypeScript` queried separately,
  then merged and re-ranked); canonical slugs are resolved (following
  renames), forks/archived/disabled repositories dropped.
- A repository qualifies only if its **root** commits both `package.json`
  and a lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, or
  `npm-shrinkwrap.json`); probing proceeds in star order until 100 qualify.
  Full algorithm: README.md "Sampling methodology".
- **Corpus caveat.** The GitHub endpoint in this environment is a mirror
  whose slug universe differs from public GitHub (verified directly:
  `react/react` resolves, `facebook/react` does not); results characterize
  this corpus, not public GitHub.
- **Selection bias.** The root-lockfile requirement skews the sample toward
  applications and root-lockfile monorepos, excluding libraries that don't
  commit a lockfile and monorepos whose packages live below the root.

### 3.2 Pipeline

Four stages, all driven by `run.py` (README.md "Commands"):

1. **Sample**: build `sample.json` (§3.1).
2. **Import**: register each repository as a CodeClarity project via a
   GitHub VCS integration.
3. **Analyze**: submit one analysis per (project, snapshot): stage 1
   `js-sbom` (SBOM from the lockfile), stage 2 `vuln-finder` (knowledge-DB
   matching, severity, EPSS) and `license-finder`. HEAD is pinned to a
   concrete commit SHA; historical snapshots target the latest
   default-branch commit at or before each grid date.
4. **Collect**: flatten persisted plugin JSON into tidy Parquet tables
   (`analyses.parquet`, `vulns.parquet`).

A separate `analyze` step mines day-resolution fix commits, then extracts
every number this document cites into `results_numbers.json` and renders
the shareable brief PDF, both computed from the same shared
`js_vuln_study/stats.py` module, so the two documents cannot disagree on a
number.

### 3.3 Measures

- **Vulnerability instance**: one (analysis, matched-advisory) row in
  `vulns.parquet`; a project's *load* is its instance count at a given
  scan.
- **`fix_kind`**: for each dated fix, git history is mined to find the
  commit where the vulnerable version left the root lockfile; the result
  is classified `upgraded` (the dependency still resolves, to a
  non-vulnerable version) or `removed` (it no longer resolves at all),
  with removals further split into `removed_direct` / `removed_transitive`
  by whether the dependency was still declared in `package.json` at the
  point it disappeared. Lockfile-level only; see §5.
- **EPSS**: an exploit-prediction score attached per instance where a CVE
  mapping exists; used as prioritization context, not a validity measure.
- **Residence-time / Kaplan-Meier**: a vulnerability's presence in a
  project's dependency tree is modeled as a survival interval; missing or
  failed snapshots are treated as right-censored, not as fixes.

### 3.4 Provenance & coverage

| Item | Value |
|------|-------|
| Knowledge sources (NVD / GCVE / OSV) | all 2026-08-29 |
| Knowledge source: npm | `"0"` (sentinel: never updated) |
| Plugin versions | js-sbom v0.0.25-alpha, vuln-finder v0.0.25-alpha, license-finder v0.0.18-alpha |
| `results_numbers.json` generated | 2026-08-30 |

- HEAD: 98 of 100 projects completed. Historical grid: 3,005 of 3,474
  submitted analyses completed (86.5%) across the 40-date grid.
- 471 analyses failed outright, concentrated in 37 repositories (the top 8
  account for 58.4% of all failures); the only recorded reason for most is
  a generic stage-0/download failure class. Failures are treated as
  censoring in the residence-time analysis (§5).

### 3.5 Data status

This document is synced to `studies/top100/tables/results_numbers.json`,
generated 2026-08-30 against the corpus resampled 2026-08-29
(`sample.json`, sharing 95 of its 100 repositories with the prior draw).
**Known gap**: the `direct_only` sensitivity subset is currently
unpopulated in this run. The `direct_dependency` flag is not being set by
the current pipeline, and the subset is omitted below pending a fix,
rather than carried forward with stale or fabricated numbers.

## 4. Results

### 4.1 Fix-speed heterogeneity & the fast-responder tail

- Day-resolution mining pinned an exact fix commit for 84.7% of dated fix
  events (7,881 of 9,307), letting fix speed be measured in days rather
  than snapshot brackets.
- Among disclosed vulnerabilities with an exactly-dated fix, severity does
  not predict fix speed: median days-to-fix is MEDIUM 150, HIGH 160, LOW
  204, and **CRITICAL slowest at 216**.
- A fast minority sits inside those medians: about 15% of dated fixes land
  within a week of disclosure, and 61% within a quarter.
- Classifying every dated fix (the larger all-intervals day-resolution set,
  n=16,789): 68.0% are genuine upgrades, 31.9% are dependency removals
  (28.4% transitive, 3.5% direct or legacy-unsplit), the remainder
  anomalous and flagged rather than silently kept. Removals resolve faster
  than upgrades, so pooling the two compresses apparent severity
  differences. Restricted to upgrades only, the CRITICAL-to-LOW spread
  widens from 394–703 days (all fix kinds) to 467–1,067, though HIGH
  (907 days) still fixes slower than MEDIUM (741) even after excluding
  removals.

### 4.2 Concentration of exposure

- Just 10 of 277 vulnerable packages (3.6%) account for 50% of all 16,304
  instances across the 98-project HEAD corpus; 35 packages account for
  80%, 61 for 90% (Gini 0.833 by package).
- The five most systemic packages, by number of projects in which they
  appear as a vulnerable dependency: `brace-expansion` (75 of 98),
  `nanoid` (60), `js-yaml` (54), `negotiator` (48), `fast-uri` (43).
- This concentration is stable under sensitivity checks: dropping
  low-confidence matches (`match_correct_only`: 74/98 affected, 75.5%,
  load median 18.5, Gini 0.833) or provisionally-withdrawn advisories
  (`non_withdrawn`: 87/98 affected, load median 28.0, Gini 0.834) barely
  moves the concentration metrics, though it does move absolute counts.
  (`direct_only` is currently unpopulated in this run, see §3.5, and is
  omitted.)

### 4.3 Popularity does not predict security

- Across 97 projects with at least one dependency, the Spearman
  correlation between star rank and vulnerability-instance count is
  **rho = 0.015, p = 0.88**, statistically indistinguishable from zero.
  Being more popular confers no measurable security advantage in this
  corpus.

### 4.4 Supporting context

- **Prevalence.** 87 of 98 HEAD-scanned projects (88.8%) currently ship at
  least one known-vulnerable dependency. Severity mix of the 16,304
  instances: 473 CRITICAL, 6,961 HIGH, 5,277 MEDIUM, 1,149 LOW, 2,444
  unclassed (NONE).
- **Match confidence.** 13,111 instances (80.4%) are high-confidence
  (`MATCH_CORRECT`); 3,193 (19.6%) are `MATCH_POSSIBLE_INCORRECT`.
  Concentration conclusions hold in the high-confidence-only subset (§4.2);
  absolute counts shift.
- **Knowledge source mix.** OSV wins 79.5% of matches (12,966), GCVE 18.2%
  (2,972), NVD 2.2% (366).
- **EPSS coverage.** 94.4% of instances carry an EPSS score; median
  0.0017, 90th percentile 0.0062; 186 instances score above 0.1, 107 above
  0.5. This is exploit-likelihood context, not a validity measure.
- **Package manager** (descriptive only, confounded by dependency-tree
  size): NPM projects (n=38) have a median 648 dependencies / 24.5
  vulnerabilities; PNPM (n=43) 2,058 deps / 28.0 vulns; YARN (n=17) 15,884
  deps / 221.0 vulns.
- **Longitudinal trend** (balanced 46-project panel, point-in-time
  counting): mean load holds roughly flat between 14.5 and 26.3
  instances/project from 2022-01 through 2026-02, then rises sharply to
  44–55 across the final six months of the grid (2026-03 through 2026-08),
  the snapshots closest to the knowledge-DB pin, where remediation has
  had the least time to act. Read the end-of-series rise cautiously (§5).
- 56.3% of advisories in the underlying disclosure data lack a publication
  date; "since disclosure" analyses (§4.1) are computed on the half that
  has one.

## 5. Limitations / Threats to Validity

- **Corpus & sampling.** The GitHub endpoint in this environment is a
  mirror whose slug universe differs from public GitHub; results
  characterize this corpus, not public GitHub. The root-lockfile
  requirement skews the sample toward applications and root-lockfile
  monorepos; the longitudinal panel additionally over-represents
  long-lived repositories. Corpora sampled from a different GitHub
  endpoint would contain different repositories, so cross-environment
  comparisons are corpus-level only.
- **Knowledge-snapshot dependence.** Every count is a function of the
  knowledge-DB snapshot in §3.4 (NVD/GCVE/OSV as of 2026-08-29); a rerun
  after a knowledge update counts a different CVE universe and is not
  directly comparable. The provenance record does not capture OSV's
  last-update timestamp even though OSV wins 79.5% of matches; npm's
  `"0"` sentinel means that source contributes nothing.
- **Measurement & matching.** Of 16,304 HEAD instances, 19.6% are
  lower-confidence (`MATCH_POSSIBLE_INCORRECT`) matches (§4.4). The
  `direct_dependency` flag is an SBOM heuristic, not a precise
  install-tree measure (and is currently unpopulated; see §3.5).
  `fix_kind` (§3.3) reads only the resolved tree at the fix commit: a
  `removed` verdict cannot always cleanly distinguish a deliberately
  dropped direct dependency from a transitive one that vanished when its
  parent was upgraded, and quarter-resolution fixes carry no `fix_kind`
  classification at all.
- **Coverage & censoring.** 471 of the submitted analyses failed outright,
  concentrated in 37 repositories; the gaps are treated as right-censoring
  in the residence-time analysis, which is unbiased only if censoring is
  non-informative; repository-concentrated download failures may violate
  that. Day-resolution mining depends on lockfile-history discoverability
  (84.7% yield); the remainder is excluded from the day-resolution KM
  fits.
- **Single-scanner dependence.** Headline counts come from one pipeline
  (`vuln-finder`); no independent cross-scanner validation is currently
  regenerable in this tree (a prior triangulation exercise exists only as
  retired code; see §6).

## 6. Reproducibility & Regeneration

```bash
cd experiments/js-vuln-study
python run.py sample studies/top100        # rarely needed: sample.json is committed
python run.py run studies/top100           # provision, submit, poll, retry, collect
python run.py analyze studies/top100       # mine-lag, results_numbers.json, brief.pdf
```

Full command reference, prerequisites, and the day-resolution/
knowledge-staleness mechanisms are in README.md ("Commands", "Sampling
methodology", "Snapshot grid", "Day-resolution remediation lag").

**Revision notes**:

- 2026-08-29: `studies/top100/sample.json` was re-sampled (95 of 100
  repositories shared with the prior draw); every number in this document
  reflects the resampled corpus.
- `fix_kind: "removed"` was split into `removed_direct` /
  `removed_transitive` (`js_vuln_study/miner.py::classify_removal`).
- Three analyses formerly reported in this document (an independent-
  scanner triangulation, a knowledge-staleness dose-response ladder, and a
  June→August drift decomposition) were retired along with the harness
  simplification that removed their generating scripts
  (`scripts/triangulate.py`, `scripts/ladder_dose_response.py`,
  `scripts/drift_decomposition.py`); see git history for the prior prose.
  The mechanisms they used (`frozen_from`, `knowledge_asof`) still work for
  building new ladder rungs, but a new cross-rung aggregator would need to
  be written.
- The Passbolt-vs-top100 cohort comparison is reported only in the brief
  (`studies/passbolt/report/brief.pdf`, via `run.py analyze
  studies/passbolt --baseline studies/top100`), not in this document.
