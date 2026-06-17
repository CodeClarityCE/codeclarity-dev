# Analysis notebooks

`analysis.py` is a jupytext-compatible `# %% ` notebook. It drives the three
Parquet tables produced by `python run.py collect` for a **cross-sectional
measurement study** of the 100 most-starred GitHub JavaScript/TypeScript repos
at HEAD, headlined on **supply-chain risk concentration**.

## Running

Two options — both work without converting to `.ipynb`:

1. **VS Code / Cursor**: open `analysis.py`. Each `# %%` block becomes a
   runnable cell (the "Python: Run Current Cell" action, `Shift+Enter`).
2. **Terminal**: `python notebooks/analysis.py` runs every cell top to bottom.
   Useful for regression-testing the schema after an orchestrator change.

## PDF report

`report.py` renders a knit-style PDF (prose + figures + tables) from the same
parquet tables — the equivalent of knitting an R Markdown report. The dev box has
no LaTeX/quarto, so it uses matplotlib (figures) + reportlab (layout), no system
deps:

```bash
python notebooks/report.py      # -> data/report/js-vuln-study-report.pdf
```

## Structure

Each section stands on its own — cells skip gracefully when the underlying
data is missing (no longitudinal snapshots yet, no EPSS on some CVEs, etc.).

| Section | Content / figure                                                            |
|---------|----------------------------------------------------------------------------|
| 0       | Setup, dependency-free stat helpers (`gini`, `lorenz`, `ecdf`, `pairwise_mwu`), and a data-quality/threats-to-validity preamble |
| RQ-A    | Prevalence & severity — % projects affected, vuln-load ECDF, severity mix, CVSS distribution |
| RQ-B    | **Concentration & hotspots (headline)** — top vulnerable packages by project spread, widespread (package, CVE) and shared (package, version), Lorenz curves + Gini |
| RQ-C    | Popularity vs security — Spearman of star rank vs vuln load (null result)   |
| RQ-D    | Package-manager differences — normalised vuln density, Kruskal–Wallis + Bonferroni MWU posthoc, direct→transitive amplification |
| RQ-E    | Measurement caveats — source-conflict crosstab, threats-to-validity checklist |

The cells produce draft figures and the headline numbers, not final publication
graphics — copy the salient cells into a curated `figures.py` (or LaTeX-ready
pgfplots) for the manuscript once the analysis settles.
