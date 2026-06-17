# Findings memo — Dependency-vulnerability landscape of top GitHub JS/TS projects

> Working brief for a scientific write-up, derived from `data/tables/{analyses,vulns}.parquet`.
> **All cross-sectional numbers are HEAD-only** (the consistent single-timepoint population).
> Regenerate with `notebooks/report.py` (PDF) / `notebooks/analysis.py` (notebook).
> **Dataset:** fresh clean run, 2026-06 — 90 projects analysed at HEAD (of 100 sampled),
> plus 18 historical quarterly snapshots (625 analyses total across 19 dates).

## 0. Read this first — population & data provenance

The `vulns` table spans **19 snapshots** (HEAD + 18 historical quarters), so a vulnerability
present across many quarters appears as many rows. Every cross-sectional statistic therefore runs
on the **HEAD slice only** (guarded by asserts in `report.py`); only the point-in-time trajectory
uses the full multi-snapshot table. This fixes an earlier bug that mixed the two populations
(counting each project ~18× over and producing artifacts like "brace-expansion in 39/37 projects").

Headline numbers from the clean HEAD cross-section (n=90 projects):

| Metric | Value |
|---|---|
| Repos with ≥1 known-vuln dependency | **66 / 90 (73%)** |
| Vulnerability instances (HEAD) | **5,094** |
| Distinct vulnerable packages | **206** |
| Vulns / project (median / mean / max) | **8 / 57 / 1,356** |
| Top-10 packages' share | **49%** (Gini 0.77) |
| Top-10 projects' share | **74%** (Gini 0.83) |
| Packages to clear 50 / 80 / 90% | **11 / 36 / 62** |
| Most systemic packages | **brace-expansion 36, uuid 29, ws 23, picomatch 23, esbuild 21** |
| High+critical share | **42%** (235 critical / 1,888 high) |

## 1. Framing & contributions

1. **Corrected cross-sectional measurement** of known-vulnerable dependency exposure in the
   most-starred GitHub JS/TS projects at HEAD.
2. **Point-in-time-correct longitudinal trajectory** (the novel angle): at each historical
   snapshot we count only vulnerabilities *already disclosed by that date* using the dependency
   tree *present then* — avoiding the common anachronism of judging old code by today's CVE DB.

## 2. Research questions (labels reused from `analysis.py`)

- **RQ-A** Prevalence & severity at HEAD.
- **RQ-B** Concentration & hotspots + remediation leverage (the headline).
- **RQ-C** Does popularity predict vulnerability load?
- **RQ-D** Package-manager differences (descriptive, confounded by size).
- **RQ-E** Measurement quality / threats.
- **RQ-F** Vulnerability evolution (disclosure timeline + point-in-time trajectory).

## 3. Headline results (HEAD, n=90 projects, 5,094 instances)

- **Prevalence.** 66/90 (73%) ship ≥1 known-vulnerable dependency. Load is heavy-tailed:
  median **8**, mean **57**, max **1,356** vulns/project — lead with medians/IQR, not means.
- **Severity skews high.** critical=235, high=1,888, medium=2,083, low=353, none=535 →
  **42%** of classified instances are high/critical.
- **Concentration.** Top-10 packages cause **49%** of instances (Gini 0.77); top-10 projects
  hold **74%** (Gini 0.83). Lorenz curves far from the diagonal.

## 4. Remediation leverage (the actionable result)

Ranking packages by instance count: **11** upstream packages clear **50%** of all instances,
**36** clear 80%, **62** clear 90%. The most systemic packages are mostly small, widely-reused,
largely transitive utilities:

| Package | # projects affected (of 90) |
|---|---|
| brace-expansion | 36 |
| uuid | 29 |
| ws | 23 |
| picomatch | 23 |
| esbuild | 21 |
| lodash | 20 |

**Takeaway:** ecosystem-wide risk is a fixable Pareto — a handful of upstream maintainers /
pinned bumps clear most measured exposure.

## 5. Popularity vs security (report honestly — do not call it a clean null)

- Raw count: Spearman ρ=**+0.16**, p=**0.14**, n=88 → not significant; a weak positive trend,
  so **underpowered**, not a definitive null. (On the smaller 37-project run this was ρ=+0.27;
  the direction is stable, the magnitude small.)
- Worth re-checking on this larger sample: normalised density (vulns / 1k deps) vs rank — on the
  earlier run this was a weak-but-significant positive trend (less-popular → denser); present any
  such result as suggestive, not conclusive (no multiplicity correction).

## 6. Package-manager differences (RQ-D, descriptive only)

NPM 36 / PNPM 36 / YARN 16 projects. YARN median deps = 7,910 (vs NPM 687 / PNPM 2,159) — driven
by large monorepos, so size-confounded; YARN median vulns 83 vs NPM 7 / PNPM 3.5. Normalise to
vulns-per-1k-deps and keep strictly descriptive (no causal PM claim).

## 7. Measurement quality (RQ-E) — a sub-study, not just a caveat

- **Match confidence:** 930/5,094 HEAD matches (**18%**) flagged `MATCH_POSSIBLE_INCORRECT`.
  **Sensitivity result (in the report):** restricting to the high-confidence subset (4,164
  matches, 82%) leaves the headline intact — top-10 packages' share **49%** (unchanged),
  packages-to-clear-50% **11** (unchanged). The concentration and remediation findings **do not
  depend on the dubious matches.**
- **Direct/transitive:** a non-trivial share are flagged direct (the old "all transitive" claim
  was wrong). Report descriptively; the flag is not a precise install-tree measure.
- **EPSS / winning_source:** genuinely 100% empty → no exploit-likelihood prioritisation here.

## 8. Evolution (RQ-F)

- **Disclosure timeline (HEAD, deps fixed today):** dating the present vulnerabilities by advisory
  publication shows a recency-of-disclosure concentration. Frame as *"how recently the risk in
  today's trees was disclosed,"* **not** a trend in the projects (no LLM-era causal claim).
- **Point-in-time trajectory (the contribution):** the longitudinal run covers 19 dates with
  23–42 projects completed per historical date. The all-projects mean is composition-confounded
  (panel size grows over time). **Balanced-panel result (Fig 7):** restricting to the **6 projects
  analysed at *every* one of the 18 snapshots** (zero-filled) gives the like-for-like point-in-time
  trend — low historical load (~5 vulns/proj in 2022, point-in-time-correct) rising to ~17 at
  2026-Q2. Honest but **noisy at n=6**. The balanced panel is small because ~840 historical
  analyses wedged in this synthetic env (downloader can't resolve old commits), leaving per-project
  gaps; on a real GitHub corpus with full historical coverage the panel would be far larger
  (20 projects appear in ≥15 of 18 snapshots here — a near-balanced fallback).

## 9. Threats to validity (corrected, ordered by severity)

1. **Selection bias.** 90/100 sampled repos produced a clean HEAD scan (10 had no resolvable
   dependency tree / failed SBOM). Historical coverage is partial (~840/1,525 snapshot analyses
   wedged), so longitudinal claims rest on a smaller balanced panel — the dominant longitudinal
   threat.
2. **Match quality.** ~18% possibly-incorrect matches; addressed by the sensitivity analysis above.
3. **Single scanner.** All matches from one tool (CodeClarity); absolute counts are
   scanner-dependent — ideally triangulate against `npm audit` / OSV-Scanner / Dependabot.
4. **Disclosure recency** for the HEAD timeline; **panel composition** for the longitudinal view.
5. **No exploit prioritisation** (EPSS empty).
6. **Sample hygiene.** The prior sample included oddities — e.g. `affaan-m/ECC` at star-rank 4
   and `react/react` (vs the canonical `facebook/react` slug). `js_vuln_study/sample.py` now drops
   `fork`/`archived`/`disabled` repos, and the fresh run re-samples with `--refresh`. Still verify
   the top-N are the intended canonical repos (the sandboxed GitHub endpoint may return synthetic
   slugs, in which case the filter is correct but the sample is unchanged).

## 10. Related-work hooks (TODO — find real citations, do not fabricate)

- npm-ecosystem dependency-vulnerability measurement studies (prevalence at scale).
- Transitive-vulnerability propagation / "small utility, huge blast radius."
- Remediation-leverage / Pareto-of-fixes and upstream-bump impact studies.
- Point-in-time / time-travel methodology for avoiding CVE-DB anachronism.

## 11. Suggested next analyses

- **Balanced-panel longitudinal** re-run + per-project survival of individual CVEs (time-to-fix).
- **Sensitivity analysis** excluding `MATCH_POSSIBLE_INCORRECT` for every headline number.
- **Multi-scanner triangulation** on a subsample to bound scanner-specific error.
- **Re-sample** to a clean canonical top-100 and re-check whether the lockfile-exclusion bias
  shifts prevalence.
