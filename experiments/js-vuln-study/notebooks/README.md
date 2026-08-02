# Analysis notebooks

`analysis.py` is a jupytext-compatible `# %%` notebook. It drives the Parquet
tables produced by `python run.py collect` (see `../DATA_DICTIONARY.md` for
every column): a **cross-sectional measurement study** of the most-starred
GitHub JS/TS repos at HEAD, headlined on **supply-chain risk concentration**,
plus longitudinal sections that activate when the tables contain historical
snapshots.

Discipline shared by every cell: the `vulns` table spans all snapshots, so
**cross-sectional statistics run on the HEAD slice only** — otherwise each
project is counted once per snapshot (~19×). Only the point-in-time and
survival sections use the full multi-snapshot frame.

## Running

Two options — both work without converting to `.ipynb`:

1. **VS Code / Cursor**: open `analysis.py`. Each `# %%` block becomes a
   runnable cell ("Python: Run Current Cell", `Shift+Enter`).
2. **Terminal**: `MPLBACKEND=Agg .venv/bin/python notebooks/analysis.py` runs
   every cell top to bottom. Useful for regression-testing the schema after an
   orchestrator change.

## PDF report

`report.py` renders a knit-style PDF (prose + figures + tables) **from the
same parquet tables** — the equivalent of knitting an R Markdown report. The
dev box has no LaTeX/quarto, so it uses matplotlib (figures) + reportlab
(layout), no system deps:

```bash
.venv/bin/python notebooks/report.py    # -> data/report/js-vuln-study-report.pdf
```

`analysis.py` and `report.py` compute the same numbers from the same shared
helpers, so the notebook and the report cannot drift apart.

## Shared statistics module — `js_vuln_study/stats.py`

*(Landing in the current change set — until it merges, `analysis.py` and
`report.py` carry inline copies of `gini`/`lorenz`/`headline`.)*

Both the notebook and the report import from `js_vuln_study.stats`, the single
source of truth for every headline number. Contract:

- `gini(values) -> float` — Gini coefficient (0 = equal, → 1 = concentrated;
  NaN on empty/all-zero input).
- `lorenz(values) -> (cum_share_x, cum_share_y)` — Lorenz-curve points.
- `pkgs_to_clear(instance_counts, share) -> int` — how many top packages
  (ranked by instance count) are needed to cover `share` of all instances.
- `headline(vulns_head, analyses_head) -> dict` — the paper's headline
  metrics from the HEAD slices. Keys: `n_projects`, `n_affected`,
  `affected_share`, `instances`, `distinct_vuln_packages`, `load_median`,
  `load_mean`, `load_max`, `sev_counts` (dict), `high_critical_share`,
  `top10_pkg_share`, `top10_proj_share`, `gini_pkg`, `gini_proj`,
  `pkgs_clear_50`, `pkgs_clear_80`, `pkgs_clear_90`, `top_packages`
  (list of `(name, n_projects)`).
- `sensitivity_sweep(vulns_head, analyses_head) -> DataFrame` — one row per
  subset, columns = the scalar headline metrics. Subsets: `all`,
  `match_correct_only` (`conflict_flag == "MATCH_CORRECT"`), `non_withdrawn`
  (`withdrawn_date` null), `direct_only` (`direct_dependency`). The rendered
  table shows at a glance which headline numbers survive each restriction.
- `presence_intervals(vulns, analyses) -> DataFrame` — longitudinal input for
  survival analysis: one row per `(project_id, vulnerability_id,
  affected_dependency)` with `first_seen`, `last_seen` (snapshot dates),
  `duration_days`, and `event` — `1` = fixed (absent at the project's **next
  completed snapshot**), `0` = censored (still present at the project's last
  completed snapshot, **or** a coverage gap follows). Only transitions between
  consecutive completed snapshots of the same project count; gaps censor
  rather than being read as fixes.
- `km_curve(duration_days, event) -> (times, survival)` — numpy Kaplan–Meier
  estimator, no new dependencies.

## Structure

Each section stands on its own — cells skip gracefully when the underlying
data is missing (`dependencies.parquet` collected with `--no-deps`, HEAD-only
data without snapshots, empty EPSS, etc.).

| Section | Content / figure |
|---------|------------------|
| 0       | Setup, shared stat helpers, and a data-quality / threats-to-validity preamble |
| RQ-A    | Prevalence & severity — % projects affected, vuln-load ECDF, severity mix, CVSS distribution |
| RQ-B    | **Concentration & hotspots (headline)** — top vulnerable packages by project spread, widespread (package, CVE) and shared (package, version), Lorenz curves + Gini, remediation leverage (`pkgs_to_clear`), and the **sensitivity-sweep table** |
| RQ-C    | Popularity vs security — Spearman of star rank vs vuln load (underpowered weak positive, not a clean null) |
| RQ-D    | Package-manager differences — normalized vuln density, Kruskal–Wallis + Bonferroni MWU posthoc, direct→transitive amplification (descriptive; size-confounded) |
| RQ-E    | Measurement caveats — source-conflict crosstab, threats-to-validity checklist |
| RQ-F    | Evolution — disclosure timeline (deps fixed at HEAD) + point-in-time per-project trajectories with a balanced-panel view |
| RQ-G    | **Per-CVE time-to-fix survival** — `presence_intervals` + `km_curve` over the longitudinal panel; censoring-aware, so coverage gaps do not masquerade as fixes |

The cells produce draft figures and the headline numbers, not final
graphics — copy the salient cells into a curated `figures.py` once the
analysis settles.
