# Results

Canonical results document for the JS/TS dependency-vulnerability measurement
study. Every number below is taken from
[`data/tables/results_numbers.json`](data/tables/results_numbers.json)
(generated from the Parquet tables by `scripts/extract_results_numbers.py`)
or from
[`data/tables/run_meta.json`](data/tables/run_meta.json). Metric definitions
are in [DATA_DICTIONARY.md](DATA_DICTIONARY.md); methodology and reproduction
commands are in [README.md](README.md). Threats to validity are collected in
[§14](#14-threats-to-validity); individual results reference them inline.

## 1. Abstract

We measured known-vulnerable-dependency exposure in the 100 most-starred
JavaScript/TypeScript repositories reachable through this environment's GitHub
endpoint that commit a root `package.json` and lockfile, scanning each
repository through the CodeClarity pipeline (js-sbom, vuln-finder,
license-finder) at a pinned HEAD commit and at 18 quarterly snapshots
(2022-Q1 through 2026-Q2). Cross-sectionally, 83 of 98 completed HEAD scans
(84.7%) carried at least one vulnerability instance, with a median load of 19
instances per project but a heavily concentrated distribution: the top 15
packages account for 50% of all 11,808 instances (Gini 0.798 by package).
Longitudinally, a balanced 50-project panel shows a roughly flat
point-in-time mean load between 15.58 and 27.08 instances across the full
2022–2025 series, rising to 55.0 at the final snapshot, which lies closest to
the knowledge-DB snapshot date. Findings were stress-tested with a
four-subset sensitivity sweep and bounded by an independent-scanner
triangulation on a 20-project subsample; all counts are conditional on this
run's corpus and knowledge-database snapshot (§14, threats 1–2).

## 2. Study design

The pipeline has four stages, all driven by `run.py` (commands in
[README.md](README.md), §Workflow):

1. **Sample** — rank repositories by stars via the environment's GitHub
   search API for `language:JavaScript` and `language:TypeScript`, resolve
   canonical slugs, and keep the top repositories that commit both a root
   `package.json` and a lockfile (§4).
2. **Import** — register each repository as a CodeClarity project via the
   REST API, using a GitHub integration for cloning.
3. **Analyze** — submit one analysis per (project, snapshot): stage 1 runs
   `js-sbom` (SBOM from the lockfile), stage 2 runs `vuln-finder`
   (knowledge-DB matching, severity, EPSS attachment) and `license-finder`.
   HEAD submissions are pinned to a concrete commit SHA; historical
   submissions target the latest default-branch commit at or before each grid
   date.
4. **Collect** — persist raw plugin JSON and derive tidy Parquet tables
   (`analyses`, `vulns`, plus `coverage_dropped.csv` and `run_meta.json`),
   with schemas documented column by column in
   [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

Statistics are computed by the shared module `js_vuln_study/stats.py`
(consumed identically by `notebooks/analysis.py` and `notebooks/report.py`);
triangulation by `js_vuln_study/triangulate.py`. Cross-sectional statistics
use the HEAD slice only; the multi-snapshot frame feeds only the longitudinal
(§11) and residence-time survival (§12) sections.

## 3. Provenance

Vulnerability counts are a function of the knowledge-database snapshot below.
A rerun after a knowledge update counts against a different CVE universe and
is not directly comparable (§14, threat 2).

| Item | Value |
|------|-------|
| Knowledge source: NVD last update | 2026-06-29T18:48:22.485Z |
| Knowledge source: GCVE last update | 2026-06-29T18:48:36.331Z |
| Knowledge source: npm | `"0"` (sentinel: never updated) |
| EPSS table rows | 344,728 |
| Plugin: js-sbom | v0.0.25-alpha |
| Plugin: vuln-finder | v0.0.25-alpha |
| Plugin: license-finder | v0.0.18-alpha |
| API version | 0.0.48-alpha |
| Experiment (monorepo) SHA | `a2f2ed54f303748ade84343061f339899e98b9aa` (clean tree as recorded at submit time, `experiment_dirty=false`) |
| API submodule SHA | `a3618c85b8ca35effc0698465cf04de8620c56a4` |
| Backend submodule SHA | `0593cd9a3fbd43289a11361a77191ae491390fee` |
| Provenance record timestamp | 2026-08-02T19:24:28Z |
| Run id | `4eebeae8-8688-4694-a5cf-26549934e39d` |

Two gaps in this record: the provenance endpoint does not expose a
last-update timestamp for OSV, although OSV is the winning source for 81.0%
of HEAD instance matches (`winning_source_head`: OSV 9,563, GCVE 1,798, NVD
447), so the snapshot pin is incomplete for the dominant source; and the npm
source's `"0"` sentinel means that source contributes nothing (§14, threat
2).

## 4. Sampling and population

`run.py sample` selects repositories by descending star count from the
environment's GitHub search endpoint, one query per language (JavaScript,
TypeScript), then merges and re-ranks. Candidates are resolved to canonical
slugs (following renames) and de-duplicated; forks, archived, and disabled
repositories are dropped. A repository qualifies only if its **repository
root** commits both a `package.json` and a lockfile (`package-lock.json`,
`yarn.lock`, `pnpm-lock.yaml`, or `npm-shrinkwrap.json`); probing proceeds in
star order until 100 qualify.

**Selection bias.** The root-lockfile requirement excludes popular libraries
that deliberately do not commit a lockfile and monorepos whose packages live
below the root. The sample therefore skews toward applications and monorepos
with parseable root lockfiles (§14, threat 3).

**Corpus caveat.** The GitHub API in this environment is a mirror whose slug
universe differs from public GitHub — verified directly: `react/react`
resolves while `facebook/react` does not. Star ranks, repository identities,
and therefore every downstream statistic characterize **this corpus**, not
public GitHub (§14, threat 1).

## 5. Coverage

Of 1,648 submitted analyses, 1,423 completed and 225 ended in failure; one
further attempt is recorded only as a pre-submission skip marker and is not
counted as a submitted analysis. At HEAD, 98 of 100 projects completed.
Across the 18 historical snapshot dates, 1,325 of 1,548 attempted (project,
date) pairs completed. The balanced panel — projects completing all 18
historical snapshots — contains 50 projects; relaxing to at least 15 of 18
yields 62 projects.

Completed scans per snapshot date:

| Date | Completed | Date | Completed |
|------|-----------|------|-----------|
| 2022-01-01 | 61 | 2024-04-01 | 74 |
| 2022-04-01 | 63 | 2024-07-01 | 75 |
| 2022-07-01 | 63 | 2024-10-01 | 76 |
| 2022-10-01 | 68 | 2025-01-01 | 78 |
| 2023-01-01 | 67 | 2025-04-01 | 81 |
| 2023-04-01 | 69 | 2025-07-01 | 80 |
| 2023-07-01 | 69 | 2025-10-01 | 83 |
| 2023-10-01 | 69 | 2026-01-01 | 85 |
| 2024-01-01 | 71 | 2026-04-01 | 93 |

Counts rise toward the present partly because repositories that did not yet
exist at earlier dates are skipped by design (unbalanced panel; §11 uses the
balanced panel to avoid composition confounding). Every dropped attempt is
recorded with its reason in `data/tables/coverage_dropped.csv`. The 225
failures span 34 repositories, with the 8 most failure-prone accounting for
52.9% of failures; the only recorded reason is the single generic class
`failure at stage-0/download; no plugin result`. Run logs point to refusals
from the environment's git endpoint as the operators' working diagnosis, but
the recorded data does not pin down a cause. In the survival analysis (§12)
these gaps are treated as censoring rather than as fixes; Kaplan–Meier
estimates remain unbiased only if censoring is non-informative, which
repository-concentrated download failures may violate. They also thin the
longitudinal view (§14, threat 5).

## 6. Cross-sectional results (HEAD)

All figures in this section come from the 98 completed HEAD scans; the unit
is the **vulnerability instance** (one per vulnerability id × affected
dependency × workspace — see DATA_DICTIONARY.md), which double-counts a CVE
that hits multiple packages or workspaces.

**Prevalence and load.** 83 of 98 projects (84.7%) had at least one instance.
Total load: 11,808 instances across 275 distinct vulnerable package names.
Per-project load is skewed: median 19, mean 120.5, maximum 1,854 — the median
is the representative figure; the mean is dominated by a small tail of
lockfile-heavy projects.

**Severity mix.** Of the 11,808 instances: 525 CRITICAL, 4,249 HIGH, 4,304
MEDIUM, 1,066 LOW, and 1,664 with no CVSS class (NONE). HIGH plus CRITICAL
account for 40.4% of all instances.

**Concentration.** Instances concentrate in few packages and few projects:
the top 10 packages account for 39.9% of all instances and the top 10
projects for 71.1% (Gini coefficients 0.798 by package and 0.798 by project).
Ranked by instance count, the top 15 packages account for 50% of instances,
the top 42 for 80%, and the top 70 for 90% — an attribution of observed
instances, not a counterfactual removal estimate. The concentration pattern
is stable under all sensitivity subsets (§7).

Most systemic packages, by number of HEAD projects affected:

| Package | Projects affected |
|---------|-------------------|
| js-yaml | 52 |
| negotiator | 49 |
| brace-expansion | 39 |
| esbuild | 36 |
| ajv | 34 |
| uuid | 34 |
| clone | 33 |
| form-data | 33 |
| minimatch | 33 |
| qs | 32 |

These counts inherit the match-confidence caveat (§14, threat 4): a share of
instances carry a `MATCH_POSSIBLE_INCORRECT` flag, and §7 quantifies the
effect of excluding them.

## 7. Sensitivity

The headline metrics were recomputed on four subsets of the HEAD instances:
`all`, `match_correct_only` (`conflict_flag == MATCH_CORRECT`),
`non_withdrawn` (advisory not retracted), and `direct_only` (heuristic
direct-dependency flag; §14, threat 7).

| Metric | all | match_correct_only | non_withdrawn | direct_only |
|--------|-----|--------------------|---------------|-------------|
| Projects affected | 83 | 72 | 83 | 56 |
| Affected share | 84.7% | 73.5% | 84.7% | 57.1% |
| Instances | 11,808 | 9,575 | 11,334 | 1,995 |
| Distinct vulnerable packages | 275 | 238 | 268 | 124 |
| Load median | 19 | 12 | 19 | 1 |
| Load mean | 120.5 | 97.7 | 115.7 | 20.4 |
| Load max | 1,854 | 1,630 | 1,832 | 396 |
| High+critical share | 40.4% | 41.1% | 39.9% | 34.1% |
| Top-10 package share | 39.9% | 45.4% | 40.6% | 62.3% |
| Top-10 project share | 71.1% | 71.6% | 71.9% | 74.7% |
| Gini (package) | 0.798 | 0.802 | 0.798 | 0.767 |
| Gini (project) | 0.798 | 0.815 | 0.802 | 0.853 |
| Packages accounting for 50% | 15 | 12 | 15 | 6 |
| Packages accounting for 80% | 42 | 35 | 41 | 24 |
| Packages accounting for 90% | 70 | 60 | 67 | 41 |

Concentration is stable across all four subsets: the Gini coefficients stay
between 0.767 and 0.853, and the top-10 project share between 71.1% and
74.7%. Absolute counts shift materially — restricting to high-confidence
matches removes 2,233 instances and lowers the median load from 19 to 12, and
the direct-only view collapses the median to 1 — so absolute prevalence and
load figures should be read as ranges bounded by these subsets rather than
point estimates.

## 8. Exploit likelihood (EPSS)

EPSS scores were attached for 92.1% of HEAD instances (the EPSS table held
344,728 rows at run time, §3). The 938 unscored instances are mostly non-CVE
advisory ids, which have no EPSS row (898 instances); the remaining 40 are
CVE-identified instances that also lacked EPSS rows. Among
scored instances the median EPSS score is 0.0006 and the 90th percentile
0.00581; 212 instances score above 0.1 and 121 above 0.5. These figures are
prioritization context only — EPSS estimates exploitation likelihood in the
wild for the CVE, not risk in these specific deployments, and inherits the
knowledge-snapshot dependence of §14, threat 2.

## 9. Popularity vs load (RQ-C)

Spearman correlation between star rank and HEAD vulnerability load: rho =
0.0602, p = 0.558, n = 97 (of the 98 completed HEAD scans, 1 project with
zero resolved dependencies is excluded). The association is not
statistically significant and the sample is underpowered for effects of this
size; we report it as an absence of evidence for a monotone association
within this corpus, not as evidence of absence, and draw no causal
conclusion.

## 10. Package-manager differences (RQ-D)

Descriptive only. Package manager is detected from the committed lockfile,
and the groups differ strongly in dependency-multiset size, so the
vulnerability differences are size-confounded — larger resolved universes
mechanically expose more advisories (see DATA_DICTIONARY.md on
`total_dependencies` as a bloat proxy).

| Package manager | Projects | Median dependencies | Median vulnerability instances |
|-----------------|----------|---------------------|--------------------------------|
| NPM | 38 | 647.5 | 11.5 |
| PNPM | 42 | 2,133 | 19.5 |
| YARN | 18 | 8,643.5 | 129.5 |

## 11. Longitudinal trajectory (RQ-F)

Point-in-time filtering is applied at analysis time, not by the scanner:
from each historical scan's output we keep only vulnerabilities whose
publication date falls on or before the snapshot date, evaluated against the
dependency tree actually committed at that snapshot — not today's knowledge
projected backwards. Instances with unknown publication dates are excluded
by this filter — 47.6% of historical instance rows carry no publication
date, and the trajectory retains 19,778 of the panel's 235,644 historical
rows — so the levels below are lower bounds conditional on
publication-date availability. To avoid composition confounding from the
growing unbalanced panel (§5), the trajectory is computed on the balanced
panel of 50 projects that completed all 18 snapshots. Mean instances per
project at representative dates (full series in `results_numbers.json`, key
`trajectory_balanced`):

| Snapshot | Mean load (n = 50) |
|----------|--------------------|
| 2022-01-01 | 16.64 |
| 2022-04-01 | 23.76 |
| 2023-07-01 | 27.08 |
| 2024-07-01 | 17.96 |
| 2025-07-01 | 16.28 |
| 2026-01-01 | 22.92 |
| 2026-04-01 | 55.00 |

Across the full 2022–2025 series the panel mean oscillates between 15.58 and
27.08 with no clear trend. The final snapshot (55.00) should be read
cautiously: it is the closest to the knowledge-DB snapshot date (§3), where
recently disclosed advisories have had the least calendar time to be
remediated, so an end-of-series
increase is expected under point-in-time counting even without any change in
project behavior. The balanced panel also over-represents long-lived
repositories (§14, threats 3 and 5).

## 12. Vulnerable-version residence time (RQ-G)

**What this measures.** Intervals are built on all observed instances, but
most were not yet disclosed while present: 43.7% of historical instance
rows have a publication date after their snapshot and 47.6% have no
publication date at all (`disclosure_coverage_hist`). The medians below
therefore measure how long vulnerable versions persist in dependency trees,
**not** remediation lag — maintainers cannot respond to advisories that are
not yet published.

Presence intervals were built per (project, vulnerability id, affected
dependency) across each project's consecutive completed snapshots: 22,916
intervals, of which 15,414 ended with the pair disappearing (event = 1) and
7,502 were censored. Censoring semantics (from `js_vuln_study/stats.py`): an
interval ends in an event only when the pair is absent at the project's
immediately-next completed snapshot with no missing grid date in between —
coverage gaps censor the interval rather than being read as fixes, and
presence on both sides of a gap yields two separate intervals. Intervals are
also left-truncated: pairs already present at a project's first completed
snapshot have an unknown true start, so those durations are under-measured.

Kaplan–Meier median residence time by severity class (2,888 intervals with
no CVSS class are excluded from this breakdown):

| Severity | Intervals (n) | KM median (days) |
|----------|---------------|------------------|
| CRITICAL | 1,917 | 455 |
| HIGH | 7,384 | 639 |
| MEDIUM | 8,998 | 578 |
| LOW | 1,729 | 730 |

The observed ordering is not monotone in severity: CRITICAL pairs disappear
fastest (455 days), followed by MEDIUM (578), HIGH (639), and LOW slowest
(730). Durations are interval-censored at quarterly resolution — a
disappearance is observed only at the next snapshot, so all medians are
upper-bound-shifted by up to one quarter — and disappearance of a pair
includes dependency removal and version drift, not only deliberate
remediation.

**Disclosed-only robustness variant.** Restricting to rows whose
vulnerability was published on or before the snapshot (`survival_disclosed`)
collapses the data to 768 intervals with 190 observed events (578 censored),
and KM medians are mostly not reached: CRITICAL 731 days (n = 61) and LOW
303 days (n = 75), with HIGH (n = 152) and MEDIUM (n = 315) medians not
reached. This subset is underpowered, so we draw no remediation-lag
conclusions from this study.

## 13. Independent-scanner triangulation

A stratified subsample of 20 HEAD projects was re-scanned with independent
tools (`js_vuln_study/triangulate.py`), comparing normalized (package, CVE)
sets. Of the 20, 19 produced an osv-scanner comparison and 17 had a
non-empty CVE-pair union, i.e. a defined Jaccard. `npm audit` executed but
contributed no CVE-mapped advisories to the pair sets here, so CVE-level
agreement rests on osv-scanner alone (§14, threat 6). Advisories with no CVE
alias (GHSA-only) cannot be compared at the CVE level and are tallied
separately in the `*_unmapped` columns of
`data/tables/triangulation.parquet` rather than in the pair sets.

CodeClarity vs osv-scanner Jaccard agreement, by lockfile type (per
`triangulate.py`, agreement must be read per lockfile population; "defined /
total" counts projects with a non-empty pair union):

| Lockfile | Defined / total (n) | Mean Jaccard |
|----------|---------------------|--------------|
| package-lock.json | 6 / 8 | 0.485 |
| pnpm-lock.yaml | 7 / 7 | 0.274 |
| yarn.lock | 4 / 4 | 0.510 |

Against the union of independent-scanner findings — effectively osv-scanner
alone, since npm audit contributed no CVE-mapped advisories — CodeClarity's
mean per-project recall is 0.562 over the 17 projects with a defined union,
with per-project values ranging from 0.0 to 1.0. Agreement at this level is
plausibly attributable to differences in advisory sourcing and alias
completeness; it bounds, but does not eliminate, single-scanner error in the
headline counts (§14, threat 6).

## 14. Threats to validity

1. **Corpus provenance.** The environment's GitHub API is a mirror whose slug
   universe differs from public GitHub (verified: `react/react` resolves,
   `facebook/react` does not). All results characterize this corpus; external
   generalization to public GitHub is not claimed.
2. **Knowledge-snapshot dependence.** Every vulnerability count is a function
   of the knowledge-DB snapshot in §3 (NVD/GCVE updated 2026-06-29). The
   provenance endpoint does not capture OSV's last-update timestamp even
   though OSV is the winning source for 81.0% of HEAD matches, so the
   snapshot pin is incomplete for the dominant source; the npm source
   (`"0"` sentinel) contributes nothing. Runs under different snapshots
   count different CVE universes and are not directly comparable; compare
   `run_meta.json` records first (§15).
3. **Selection bias.** Requiring a root `package.json` plus lockfile excludes
   libraries that do not commit lockfiles and nested-package monorepos,
   skewing the sample toward applications and root-lockfile monorepos. The
   balanced longitudinal panel additionally over-represents long-lived
   repositories.
4. **Match confidence.** Of the 11,808 HEAD instances, 9,575 are flagged
   `MATCH_CORRECT` and 2,233 `MATCH_POSSIBLE_INCORRECT`. The sensitivity
   sweep (§7) brackets the effect: concentration conclusions hold in the
   high-confidence subset; absolute counts do not.
5. **Coverage gaps.** 225 of 1,648 submitted analyses failed, spanning 34
   repositories (the top 8 account for 52.9% of failures); the only recorded
   reason is the generic class `failure at stage-0/download; no plugin
   result`, with git-endpoint refusals the operators' working diagnosis from
   run logs. The gaps thin the panel and are treated as censoring rather
   than as fixes; Kaplan–Meier estimates remain unbiased only if censoring
   is non-informative, which repository-concentrated download failures may
   violate. The per-date table in §5 and `coverage_dropped.csv` make the
   gaps explicit.
6. **Single-scanner dependence.** Headline counts come from one pipeline.
   Triangulation (§13) bounds the error (mean recall 0.562 over the 17
   projects with a defined union, per-project range 0.0–1.0; Jaccard
   0.274–0.510 by lockfile type) but rests on a single comparison scanner
   because `npm audit` contributed no CVE-mapped advisories here.
7. **Direct/transitive heuristic.** The `direct_dependency` flag is an SBOM
   heuristic, not a precise install-tree measure; the `direct_only` subset
   (§7) and RQ-D splits are descriptive only.

## 15. Regeneration

From raw data to the numbers in this document (venv per README.md
prerequisites; each command is resumable and de-duplicating):

```bash
cd experiments/js-vuln-study
python run.py sample                      # data/sample.json (top 100)
python run.py submit --snapshots          # HEAD + 18 quarterly snapshots
python run.py poll                        # drive to terminal; safe to interrupt
python run.py retry && python run.py poll # re-drive sad-terminal rows
python run.py collect --no-deps           # data/tables/*.parquet + run_meta.json
python run.py triangulate                 # data/tables/triangulation.parquet
MPLBACKEND=Agg .venv/bin/python notebooks/analysis.py   # figures + headline cells
.venv/bin/python notebooks/report.py      # data/report/js-vuln-study-report.pdf
.venv/bin/python scripts/extract_results_numbers.py     # data/tables/results_numbers.json
```

The consolidated extraction backing this document is
`data/tables/results_numbers.json`, generated by
`scripts/extract_results_numbers.py`, alongside the provenance record
`data/tables/run_meta.json`. Before comparing any number across runs, compare
`data/tables/run_meta.json` (knowledge-source timestamps, EPSS row count,
plugin versions, SHAs) — counts produced under different knowledge snapshots
are not comparable.
