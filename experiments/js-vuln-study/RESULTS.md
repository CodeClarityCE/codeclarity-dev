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
(2022-Q1 through 2026-Q2). Cross-sectionally, 89 of 97 completed HEAD scans
(91.8%) carried at least one vulnerability instance, with a median load of 34
instances per project but a heavily concentrated distribution: the top 12
packages account for 50% of all 16,678 instances (Gini 0.832 by package).
Longitudinally, a balanced 49-project panel shows a roughly flat
point-in-time mean load between 15.4 and 27.0 instances across the full
2022–2025 series, rising to 56.6 at the final snapshot, which lies closest to
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
| Knowledge source: NVD last update | 2026-08-03T10:37:53.778Z |
| Knowledge source: GCVE last update | 2026-08-03T10:45:27.947Z |
| Knowledge source: npm | `"0"` (sentinel: never updated) |
| EPSS table rows | 355,142 |
| Plugin: js-sbom | v0.0.25-alpha |
| Plugin: vuln-finder | v0.0.25-alpha |
| Plugin: license-finder | v0.0.18-alpha |
| API version | 0.0.48-alpha |
| Experiment (monorepo) SHA | `e494cd5212e8d46e3ef640da68e67e22a9db8e30` (clean tree as recorded at submit time, `experiment_dirty=false`) |
| API submodule SHA | `a3618c85b8ca35effc0698465cf04de8620c56a4` |
| Backend submodule SHA | `96cbf693f6dd967934b45b659a76c3c0e266fafc` |
| Provenance record timestamp | 2026-08-03T11:17:48Z |
| Run id | `e12cbeb8-6d66-4021-99f7-341bad32809f` |

This run analyzed the **same 100-project sample** as the archived
2026-06-snapshot run (`data/archive-run-2026-06-snapshot/`, which carries its
own pinned provenance record and is regenerable from its archived data), so
comparisons between the two runs that attribute differences to the
knowledge-snapshot date are legitimate (used in §13). Sample identity holds
at the repository (git URL) level; the archived manifest labels one
repository under two names (`vuejs/core` / `@vue/runtime-core`), so
per-name aggregates require that normalization.

Two gaps in this record: the provenance endpoint does not expose a
last-update timestamp for OSV, although OSV is the winning source for 78.3%
of HEAD instance matches (`winning_source_head`: OSV 13,066, GCVE 3,202, NVD
410), so the snapshot pin is incomplete for the dominant source; and the npm
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

Of 1,629 submitted analyses, 1,404 completed and 225 ended in failure; one
further attempt is recorded only as a pre-submission skip marker
(`coverage.skip_markers` = 1) and is not counted as a submitted analysis.
At HEAD, 97 of 99 submitted scans completed; the HEAD total is 99 rather
than 100 because that skip marker is project-wide — snapshot resolution
timed out for one sampled project before anything was submitted, removing
its HEAD attempt and its 18 historical attempts from the denominators
alike. Across the 18 historical
snapshot dates, 1,307 of 1,530 attempted (project, date) pairs completed.
The balanced panel — projects completing all 18 historical snapshots —
contains 49 projects; relaxing to at least 15 of 18 yields 61 projects.

Completed scans per snapshot date:

| Date | Completed | Date | Completed |
|------|-----------|------|-----------|
| 2022-01-01 | 60 | 2024-04-01 | 73 |
| 2022-04-01 | 62 | 2024-07-01 | 74 |
| 2022-07-01 | 62 | 2024-10-01 | 75 |
| 2022-10-01 | 67 | 2025-01-01 | 77 |
| 2023-01-01 | 66 | 2025-04-01 | 80 |
| 2023-04-01 | 68 | 2025-07-01 | 79 |
| 2023-07-01 | 68 | 2025-10-01 | 82 |
| 2023-10-01 | 68 | 2026-01-01 | 84 |
| 2024-01-01 | 70 | 2026-04-01 | 92 |

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

All figures in this section come from the 97 completed HEAD scans; the unit
is the **vulnerability instance** (one per vulnerability id × affected
dependency × workspace — see DATA_DICTIONARY.md), which double-counts a CVE
that hits multiple packages or workspaces.

**Prevalence and load.** 89 of 97 projects (91.8%) had at least one instance.
Total load: 16,678 instances across 302 distinct vulnerable package names.
Per-project load is skewed: median 34, mean 172, maximum 2,634 — the median
is the representative figure; the mean is dominated by a small tail of
lockfile-heavy projects.

**Severity mix.** Of the 16,678 instances: 538 CRITICAL, 6,375 HIGH, 6,103
MEDIUM, 1,326 LOW, and 2,336 with no CVSS class (NONE). HIGH plus CRITICAL
account for 41.4% of all instances.

**Concentration.** Instances concentrate in few packages and few projects:
the top 10 packages account for 46.6% of all instances and the top 10
projects for 67.3% (Gini coefficients 0.832 by package and 0.772 by project).
Ranked by instance count, the top 12 packages account for 50% of instances,
the top 38 for 80%, and the top 65 for 90% — an attribution of observed
instances, not a counterfactual removal estimate. The concentration pattern
is stable under all sensitivity subsets (§7).

Most systemic packages, by number of HEAD projects affected:

| Package | Projects affected |
|---------|-------------------|
| brace-expansion | 76 |
| nanoid | 59 |
| js-yaml | 58 |
| negotiator | 49 |
| fast-uri | 44 |
| postcss | 41 |
| esbuild | 35 |
| undici | 35 |
| uuid | 34 |
| ajv | 33 |

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
| Projects affected | 89 | 83 | 89 | 60 |
| Affected share | 91.8% | 85.6% | 91.8% | 61.9% |
| Instances | 16,678 | 13,217 | 16,196 | 2,824 |
| Distinct vulnerable packages | 302 | 257 | 295 | 144 |
| Load median | 34 | 25 | 33 | 3 |
| Load mean | 172 | 136 | 167 | 29.1 |
| Load max | 2,634 | 2,347 | 2,612 | 575 |
| High+critical share | 41.4% | 45.5% | 41.1% | 31.6% |
| Top-10 package share | 46.6% | 51.2% | 47.9% | 63.4% |
| Top-10 project share | 67.3% | 70.2% | 67.7% | 70.9% |
| Gini (package) | 0.832 | 0.831 | 0.833 | 0.792 |
| Gini (project) | 0.772 | 0.793 | 0.773 | 0.838 |
| Packages accounting for 50% | 12 | 10 | 11 | 6 |
| Packages accounting for 80% | 38 | 32 | 37 | 23 |
| Packages accounting for 90% | 65 | 56 | 63 | 42 |

Concentration is stable across all four subsets: the Gini coefficients stay
between 0.772 and 0.838, and the top-10 project share between 67.3% and
70.9%. Absolute counts shift materially — restricting to high-confidence
matches removes 3,461 instances and lowers the median load from 34 to 25, and
the direct-only view collapses the median to 3 — so absolute prevalence and
load figures should be read as ranges bounded by these subsets rather than
point estimates.

## 8. Exploit likelihood (EPSS)

EPSS scores were attached for 93.2% of HEAD instances (the EPSS table held
355,142 rows at run time, §3). The 1,142 unscored instances are mostly
non-CVE advisory ids, which have no EPSS row (1,110 instances); the
remaining 32 are CVE-identified instances that also lacked EPSS rows. Among
scored instances the median EPSS score is 0.00107 and the 90th percentile
0.00508; 220 instances score above 0.1 and 125 above 0.5. These figures are
prioritization context only — EPSS estimates exploitation likelihood in the
wild for the CVE, not risk in these specific deployments, and inherits the
knowledge-snapshot dependence of §14, threat 2.

## 9. Popularity vs load (RQ-C)

Spearman correlation between star rank and HEAD vulnerability load: rho =
0.0897, p = 0.385, n = 96 (of the 97 completed HEAD scans, 1 project with
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
| NPM | 37 | 665 | 25 |
| PNPM | 42 | 2,133 | 34 |
| YARN | 18 | 8,643.5 | 210.5 |

## 11. Longitudinal trajectory (RQ-F)

Point-in-time filtering is applied at analysis time, not by the scanner:
from each historical scan's output we keep only vulnerabilities whose
publication date falls on or before the snapshot date, evaluated against the
dependency tree actually committed at that snapshot — not today's knowledge
projected backwards. Instances with unknown publication dates are excluded
by this filter — 52.8% of historical instance rows carry no publication
date, and the trajectory retains 19,766 of the panel's 275,716 historical
rows — so the levels below are lower bounds conditional on
publication-date availability. To avoid composition confounding from the
growing unbalanced panel (§5), the trajectory is computed on the balanced
panel of 49 projects that completed all 18 snapshots. Mean instances per
project at representative dates (full series in `results_numbers.json`, key
`trajectory_balanced`):

| Snapshot | Mean load (n = 49) |
|----------|--------------------|
| 2022-01-01 | 16.7 |
| 2022-04-01 | 23.9 |
| 2023-07-01 | 27.0 |
| 2024-07-01 | 18.4 |
| 2025-07-01 | 16.4 |
| 2026-01-01 | 23.5 |
| 2026-04-01 | 56.6 |

Across the full 2022–2025 series the panel mean oscillates between 15.4 and
27.0 with no clear trend. The final snapshot (56.6) should be read
cautiously: it is the closest to the knowledge-DB snapshot date (§3), where
recently disclosed advisories have had the least calendar time to be
remediated, so an end-of-series
increase is expected under point-in-time counting even without any change in
project behavior. The balanced panel also over-represents long-lived
repositories (§14, threats 3 and 5).

## 12. Vulnerable-version residence time (RQ-G)

**What this measures.** Intervals are built on all observed instances, but
most were not yet disclosed while present: 39.8% of historical instance
rows have a publication date after their snapshot and 52.8% have no
publication date at all (`disclosure_coverage_hist`). The medians in the
primary view below therefore measure how long vulnerable versions persist in
dependency trees, **not** remediation lag — maintainers cannot respond to
advisories that are not yet published. A disclosed-only variant that does
approximate remediation lag follows as a secondary result.

Presence intervals were built per (project, vulnerability id, affected
dependency) across each project's consecutive completed snapshots: 25,884
intervals, of which 16,616 ended with the pair disappearing (event = 1) and
9,268 were censored. Censoring semantics (from `js_vuln_study/stats.py`): an
interval ends in an event only when the pair is absent at the project's
immediately-next completed snapshot with no missing grid date in between —
coverage gaps censor the interval rather than being read as fixes, and
presence on both sides of a gap yields two separate intervals. Intervals are
also left-truncated: pairs already present at a project's first completed
snapshot have an unknown true start, so those durations are under-measured.

Kaplan–Meier median residence time by severity class (3,203 intervals with
no CVSS class are excluded from this breakdown):

| Severity | Intervals (n) | KM median (days) |
|----------|---------------|------------------|
| CRITICAL | 1,920 | 455 |
| HIGH | 8,635 | 730 |
| MEDIUM | 10,250 | 638 |
| LOW | 1,876 | 821 |

The observed ordering is not monotone in severity: CRITICAL pairs disappear
fastest (455 days), followed by MEDIUM (638), HIGH (730), and LOW slowest
(821). Durations are interval-censored at quarterly resolution — a
disappearance is observed only at the next snapshot, so all medians are
upper-bound-shifted by up to one quarter — and disappearance of a pair
includes dependency removal and version drift, not only deliberate
remediation.

**Disclosed-only remediation lag (secondary result).** Restricting to rows
whose vulnerability was published on or before the snapshot
(`survival_disclosed`) — the subset maintainers could actually have reacted
to, so these intervals approximate remediation lag rather than mere
residence — yields 4,936 intervals with 2,588 observed events and 2,348
censored; 8 intervals with no CVSS class are excluded from the severity
breakdown. KM medians by severity:

| Severity | Intervals (n) | KM median (days) |
|----------|---------------|------------------|
| CRITICAL | 475 | 274 |
| HIGH | 2,023 | 273 |
| MEDIUM | 2,119 | 274 |
| LOW | 311 | 295 |

The medians cluster tightly between 273 and 295 days, with no severity
gradient in this subset. The same caveats apply as for residence time —
left truncation at each project's first completed snapshot, coverage gaps
treated as censoring, quarterly interval censoring (medians
upper-bound-shifted by up to one quarter), and disappearance including
dependency removal and version drift — and the subset additionally
conditions on publication-date availability (52.8% of historical rows carry
no publication date), so it inherits the disclosure-coverage bias described
in §11.

## 13. Independent-scanner triangulation

A stratified subsample of 20 HEAD projects was re-scanned with independent
tools (`js_vuln_study/triangulate.py`), comparing normalized (package, CVE)
sets. Of the 20, 19 produced an osv-scanner comparison and 18 had a
non-empty CVE-pair union, i.e. a defined Jaccard. `npm audit` executed and
reported advisories, but — as in the archived run — none carried a CVE
identifier in this environment, so it contributed no pairs to the CVE-level
comparison; its findings are tallied in the `npm_audit_unmapped` column of
`data/tables/triangulation.parquet`. CVE-level agreement therefore rests on
osv-scanner alone, measured on the CVE-mapped slice only (§14, threat 6).

CodeClarity vs osv-scanner Jaccard agreement, by lockfile type (per
`triangulate.py`, agreement must be read per lockfile population; "defined /
total" counts projects with a non-empty pair union):

| Lockfile | Defined / total (n) | Mean Jaccard |
|----------|---------------------|--------------|
| package-lock.json | 7 / 8 | 0.565 |
| pnpm-lock.yaml | 7 / 7 | 0.502 |
| yarn.lock | 4 / 4 | 0.719 |

Against the union of independent-scanner findings, CodeClarity's mean
per-project recall is 0.854 over the 18 projects with a defined union, with
per-project values ranging from 0.136 to 1.0. The stratified subsample is
re-drawn per run, so the archived 2026-06-snapshot triangulation shares 17
of these 20 projects; restricted to that shared subset, agreement rose from
mean Jaccard 0.43 / mean recall 0.61 (archived, n=14 defined) to 0.59 /
0.84 (this run, n=15 defined) across the knowledge-snapshot change alone —
so a large share of the cross-scanner disagreement observed in the archived
run is attributable to knowledge-snapshot staleness rather than to scanner
methodology. The
residual disagreement is plausibly attributable to differences in advisory
sourcing and alias completeness; the triangulation bounds, but does not
eliminate, single-scanner error in the headline counts (§14, threat 6).

## 14. Threats to validity

1. **Corpus provenance.** The environment's GitHub API is a mirror whose slug
   universe differs from public GitHub (verified: `react/react` resolves,
   `facebook/react` does not). All results characterize this corpus; external
   generalization to public GitHub is not claimed.
2. **Knowledge-snapshot dependence.** Every vulnerability count is a function
   of the knowledge-DB snapshot in §3 (NVD/GCVE updated 2026-08-03). The
   provenance endpoint does not capture OSV's last-update timestamp even
   though OSV is the winning source for 78.3% of HEAD matches, so the
   snapshot pin is incomplete for the dominant source; the npm source
   (`"0"` sentinel) contributes nothing. Runs under different snapshots
   count different CVE universes and are not directly comparable; compare
   `run_meta.json` records first (§15).
3. **Selection bias.** Requiring a root `package.json` plus lockfile excludes
   libraries that do not commit lockfiles and nested-package monorepos,
   skewing the sample toward applications and root-lockfile monorepos. The
   balanced longitudinal panel additionally over-represents long-lived
   repositories.
4. **Match confidence.** Of the 16,678 HEAD instances, 13,217 are flagged
   `MATCH_CORRECT` and 3,461 `MATCH_POSSIBLE_INCORRECT`. The sensitivity
   sweep (§7) brackets the effect: concentration conclusions hold in the
   high-confidence subset; absolute counts do not.
5. **Coverage gaps.** 225 of 1,629 submitted analyses failed, spanning 34
   repositories (the top 8 account for 52.9% of failures); the only recorded
   reason is the generic class `failure at stage-0/download; no plugin
   result`, with git-endpoint refusals the operators' working diagnosis from
   run logs. The gaps thin the panel and are treated as censoring rather
   than as fixes; Kaplan–Meier estimates remain unbiased only if censoring
   is non-informative, which repository-concentrated download failures may
   violate. The per-date table in §5 and `coverage_dropped.csv` make the
   gaps explicit.
6. **Single-scanner dependence.** Headline counts come from one pipeline.
   Triangulation (§13) bounds the error (mean recall 0.854 over the 18
   projects with a defined union, per-project range 0.136–1.0; Jaccard
   0.502–0.719 by lockfile type). The comparison rests on osv-scanner
   alone: `npm audit`'s advisories carried no CVE identifiers in this
   environment in either run, so agreement is measured on the CVE-mapped
   slice only.
7. **Direct/transitive heuristic.** The `direct_dependency` flag is an SBOM
   heuristic, not a precise install-tree measure; the `direct_only` subset
   (§7) and RQ-D splits are descriptive only.
8. **Endpoint-dependent corpus provenance.** The sample is drawn from the
   configured GitHub endpoint's repository population (the endpoint bases
   are env-overridable; see README). Corpora sampled from different
   endpoints contain different repositories, so cross-environment
   comparisons are corpus-level, not project-level.

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
