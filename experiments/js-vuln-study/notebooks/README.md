# Analysis notebooks

`analysis.py` is a jupytext-compatible `# %% ` notebook. It drives the three
Parquet tables produced by `python run.py collect` and maps 1:1 to the research
questions and "first discoveries" in
[`/home/vscode/.claude/plans/i-want-to-write-vectorized-crab.md`](../../../.claude/plans/i-want-to-write-vectorized-crab.md).

## Running

Two options — both work without converting to `.ipynb`:

1. **VS Code / Cursor**: open `analysis.py`. Each `# %%` block becomes a
   runnable cell (the "Python: Run Current Cell" action, `Shift+Enter`).
2. **Terminal**: `python notebooks/analysis.py` runs every cell top to bottom.
   Useful for regression-testing the schema after an orchestrator change.

## Structure

Each section stands on its own — cells skip gracefully when the underlying
data is missing (no longitudinal snapshots yet, no EPSS on some CVEs, etc.).

| Section | Hypothesis / figure                                                        |
|---------|----------------------------------------------------------------------------|
| 0       | Load tables, print shapes                                                  |
| RQ1     | State at HEAD — severity mix, direct/transitive split, EPSS exposure       |
| RQ2     | Popularity effect — per-tier vuln load, Kruskal-Wallis test                |
| RQ3     | Short-term evolution — time-series (HEAD-only today; longitudinal later)   |
| RQ4     | NVD/OSV/GCVE conflict distribution                                         |
| RQ5     | Package manager (descriptive)                                              |
| 6.1     | Popularity–staleness inversion                                             |
| 6.2     | "Recent spike is transitive-only" — longitudinal direct vs transitive plot |
| 6.3     | Source-disagreement severity bias                                          |
| 6.4     | EPSS vs CVSS prioritisation gap                                            |
| 6.5     | Package-manager effect on transitive load                                  |

The cells are designed to produce drafts of the paper's figures, not final
publication graphics. Once the numbers stabilise on the full 400-project
sample, copy the salient cells into a curated `figures.py` (or LaTeX-ready
pgfplots) for the manuscript.
