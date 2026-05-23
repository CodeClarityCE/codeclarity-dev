# ruff: noqa: E402
"""Analysis notebook for the JS vulnerability-evolution study.

Each `# %%` block is a cell. Open in VS Code / PyCharm / jupytext and "Run
Current Cell" to step through. Drives the three parquet tables produced by
`python run.py collect`:

    data/tables/analyses.parquet       # one row per (project, snapshot) scan
    data/tables/vulns.parquet          # one row per (analysis, vulnerability)
    data/tables/dependencies.parquet   # one row per (analysis, dependency)

Cells map 1:1 to the research questions and "first discoveries" in
`/home/vscode/.claude/plans/i-want-to-write-vectorized-crab.md`. They're
written to run on a handful of rows as well as on a 2800-row full sample —
empty groups are skipped gracefully, not errored.
"""

# %% [markdown]
# # 0. Setup — load the three tables

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "tables"
TIER_ORDER = ["top-100", "top-1k", "top-10k", "long-tail"]

analyses = pd.read_parquet(DATA_DIR / "analyses.parquet")
vulns = pd.read_parquet(DATA_DIR / "vulns.parquet")
deps = pd.read_parquet(DATA_DIR / "dependencies.parquet")

analyses["tier"] = pd.Categorical(analyses["tier"], categories=TIER_ORDER, ordered=True)
vulns["tier"] = pd.Categorical(vulns["tier"], categories=TIER_ORDER, ordered=True)
deps["tier"] = pd.Categorical(deps["tier"], categories=TIER_ORDER, ordered=True)

print("analyses:", analyses.shape)
print("vulns:", vulns.shape)
print("deps:", deps.shape)
print("tiers:", analyses["tier"].value_counts().to_dict())

# %% [markdown]
# # RQ1 — State
# What does the vulnerability load look like at HEAD across all projects?
# Total / direct / transitive, severity mix, EPSS exposure.

# %%
# HEAD-only view; the rest is only meaningful once longitudinal data exists.
head = analyses[analyses["snapshot_date"] == "HEAD"].copy()

summary = head[[
    "total_dependencies", "direct_dependencies", "transitive_dependencies",
    "total_vulnerabilities", "vulnerable_dependencies",
    "direct_vulnerabilities", "transitive_vulnerabilities",
    "n_critical", "n_high", "n_medium", "n_low",
]].describe().round(1)
print(summary)

# %%
# Severity mix — share of CVEs by class. The first figure for the paper.
severity_cols = ["n_critical", "n_high", "n_medium", "n_low", "n_none"]
totals = head[severity_cols].sum()
if totals.sum() > 0:
    fig, ax = plt.subplots(figsize=(6, 4))
    totals.plot.bar(ax=ax, color=["#b30000", "#e34a33", "#fc8d59", "#fdcc8a", "#ddd"])
    ax.set_ylabel("CVE count (HEAD)")
    ax.set_title("RQ1: severity mix across the sample")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.show()

# %%
# Direct vs transitive split — validates the "transitive-heavy" assumption
# every prior paper makes. If direct dominates, that's already a finding.
if head["total_vulnerabilities"].sum() > 0:
    mix = pd.Series({
        "direct": head["direct_vulnerabilities"].sum(),
        "transitive": head["transitive_vulnerabilities"].sum(),
    })
    print(mix)
    print("transitive share: {:.1%}".format(mix["transitive"] / mix.sum()))

# %%
# EPSS exposure — fraction of CVEs with EPSS ≥ 0.1 (10% exploit prob in 30 d).
# Feeds the EPSS-vs-CVSS prioritisation-gap hypothesis in Section 6.
if "epss_score" in vulns.columns and vulns["epss_score"].notna().any():
    epss = vulns.dropna(subset=["epss_score"])
    print("CVEs with EPSS data:", len(epss))
    print("EPSS ≥ 0.10:", (epss["epss_score"] >= 0.10).sum())
    print("EPSS ≥ 0.50:", (epss["epss_score"] >= 0.50).sum())
    print(epss["epss_score"].describe().round(3))


# %% [markdown]
# # RQ2 — Popularity effect
# Does popularity tier predict vulnerability load, dep age, or patching
# responsiveness? This is the paper's primary research angle.

# %%
# Headline groupby — mean vulns, deps, severity per tier.
by_tier = head.groupby("tier", observed=True).agg(
    n_projects=("npm_name", "count"),
    mean_deps=("total_dependencies", "mean"),
    median_deps=("total_dependencies", "median"),
    mean_vulns=("total_vulnerabilities", "mean"),
    median_vulns=("total_vulnerabilities", "median"),
    mean_critical=("n_critical", "mean"),
    mean_high=("n_high", "mean"),
).round(2)
print(by_tier)

# %%
# Vulns-per-project box plot by tier. With enough sample size, the story
# either confirms "more popular = more secure" or the inversion hypothesis.
if len(head) >= 8:
    fig, ax = plt.subplots(figsize=(7, 4))
    head.boxplot(column="total_vulnerabilities", by="tier", ax=ax)
    ax.set_title("RQ2: vulnerabilities per project, by popularity tier")
    ax.set_ylabel("CVE count")
    plt.suptitle("")
    plt.tight_layout()
    plt.show()

# %%
# Statistical test: is the tier effect real or noise? Kruskal-Wallis, since
# vuln counts are heavy-tailed and normality assumptions are hopeless.
try:
    from scipy.stats import kruskal
    samples = [
        head.loc[head["tier"] == t, "total_vulnerabilities"].values
        for t in TIER_ORDER
        if (head["tier"] == t).any()
    ]
    if len(samples) >= 2 and all(len(s) > 1 for s in samples):
        stat, p = kruskal(*samples)
        print(f"Kruskal-Wallis: H={stat:.3f}, p={p:.4f}")
except ImportError:
    print("scipy not installed — pip install scipy to run the test")


# %% [markdown]
# # RQ3 — Short-term evolution (2024-Q4 → 2026-Q1)
# Per-tier trends of vulns, severity, and dep age over the 7 snapshot dates.
# Only meaningful once the longitudinal submit has run. Leave stubbed.

# %%
if analyses["snapshot_date"].nunique() < 2:
    print("Only HEAD snapshots present — re-run `submit` without --head-only to populate longitudinal data")
else:
    # snapshot_date is "YYYY-MM-DD" or "HEAD". Treat HEAD as today's date.
    ts = analyses.copy()
    ts["date"] = pd.to_datetime(ts["snapshot_date"].replace("HEAD", pd.Timestamp.today().strftime("%Y-%m-%d")))
    evolution = ts.groupby(["date", "tier"], observed=True)["total_vulnerabilities"].mean().unstack()
    print(evolution)

    if not evolution.empty:
        fig, ax = plt.subplots(figsize=(8, 4))
        evolution.plot(ax=ax, marker="o")
        ax.set_title("RQ3: mean vulns per project, by tier and date")
        ax.set_ylabel("CVEs per project")
        plt.tight_layout()
        plt.show()


# %% [markdown]
# # RQ4 — Data-source quality (NVD / OSV / GCVE)
# How often do the three sources disagree on the same package-version pair,
# and does disagreement concentrate in the high-severity tail?

# %%
if "conflict_flag" in vulns.columns and vulns["conflict_flag"].notna().any():
    # Crosstab of conflict flag × severity class.
    crosstab = pd.crosstab(
        vulns["conflict_flag"],
        vulns["severity_class"],
        margins=True,
    )
    print(crosstab)

    # Row-normalise to see severity-bias: for each flag class, what fraction
    # of its CVEs are critical/high vs the global baseline?
    shares = pd.crosstab(
        vulns["conflict_flag"],
        vulns["severity_class"],
        normalize="index",
    ).round(3)
    print("\nby-flag severity shares:")
    print(shares)
else:
    print("no conflict data yet")

# %%
# Which source wins most often? Proxy for "whose DB is most complete".
if "winning_source" in vulns.columns:
    print(vulns["winning_source"].value_counts(dropna=False))


# %% [markdown]
# # RQ5 — Package manager (descriptive)

# %%
# Summarise by the per-analysis package_manager scalar produced by js-sbom.
if "package_manager" in analyses.columns and analyses["package_manager"].notna().any():
    by_pm = head.groupby("package_manager", observed=True).agg(
        n_projects=("npm_name", "count"),
        mean_deps=("total_dependencies", "mean"),
        mean_vulns=("total_vulnerabilities", "mean"),
        mean_transitive=("transitive_vulnerabilities", "mean"),
    ).round(2)
    print(by_pm)


# %% [markdown]
# # 6. First discoveries — targeted hypothesis checks
# Each block below tests one of the prioritised hypotheses in the plan.

# %% [markdown]
# ## 6.1 Popularity–staleness inversion
# Do top-100 projects carry OLDER deps than long-tail, despite more maintainer attention?

# %%
# We don't compute dep age per-row yet (it needs release-date joins); use
# deprecated / outdated flags as a rough proxy. Populate properly when the
# dependencies table gains `release` timestamps.
if "deprecated" in deps.columns:
    staleness = deps.groupby("tier", observed=True).agg(
        n_deps=("name", "count"),
        pct_deprecated=("deprecated", "mean"),
    )
    staleness["pct_deprecated"] *= 100
    print(staleness.round(2))


# %% [markdown]
# ## 6.2 Is the recent spike transitive-only?
# Requires longitudinal data. Plot direct vs transitive vuln counts over time.

# %%
if analyses["snapshot_date"].nunique() >= 2:
    ts = analyses.copy()
    ts["date"] = pd.to_datetime(ts["snapshot_date"].replace("HEAD", pd.Timestamp.today().strftime("%Y-%m-%d")))
    split = ts.groupby("date")[["direct_vulnerabilities", "transitive_vulnerabilities"]].mean()
    print(split)
    if not split.empty:
        fig, ax = plt.subplots(figsize=(8, 4))
        split.plot(ax=ax, marker="o")
        ax.set_title("Direct vs transitive vulns over time")
        ax.set_ylabel("Mean CVEs per project")
        plt.tight_layout()
        plt.show()


# %% [markdown]
# ## 6.3 Source-disagreement is severity-biased
# Already touched in RQ4. The specific test: is the rate of
# `MATCH_INCORRECT` higher among critical CVEs than among all CVEs?

# %%
if "conflict_flag" in vulns.columns and vulns["conflict_flag"].notna().any():
    overall_rate = (vulns["conflict_flag"] == "MATCH_INCORRECT").mean()
    critical_rate = (
        vulns.loc[vulns["severity_class"] == "CRITICAL", "conflict_flag"] == "MATCH_INCORRECT"
    ).mean()
    print(f"MATCH_INCORRECT rate overall:   {overall_rate:.3f}")
    print(f"MATCH_INCORRECT rate critical:  {critical_rate:.3f}")


# %% [markdown]
# ## 6.4 EPSS vs CVSS prioritisation gap
# Fraction of CRITICAL-CVSS vulns with EPSS < 1st percentile (noise), and
# fraction of LOW-CVSS vulns with EPSS > 90th percentile (sleeper threats).

# %%
if "epss_score" in vulns.columns and vulns["epss_score"].notna().any():
    e = vulns.dropna(subset=["epss_score", "severity_class"])
    q01 = np.quantile(e["epss_score"], 0.01)
    q90 = np.quantile(e["epss_score"], 0.90)
    print(f"EPSS 1st percentile: {q01:.4f}   90th percentile: {q90:.4f}")

    critical = e[e["severity_class"] == "CRITICAL"]
    low = e[e["severity_class"] == "LOW"]
    if len(critical) and len(low):
        print(f"Critical CVSS, EPSS < 1st pct: {(critical['epss_score'] < q01).mean():.2%}")
        print(f"Low CVSS,      EPSS > 90th pct: {(low['epss_score'] > q90).mean():.2%}")


# %% [markdown]
# ## 6.5 Package-manager effect on transitive load
# pnpm's strict hoisting should (hypothesis) lower transitive counts vs npm/yarn.

# %%
if "package_manager" in head.columns and head["package_manager"].notna().any():
    pm_transit = head.groupby("package_manager", observed=True).agg(
        n=("npm_name", "count"),
        mean_transitive_vulns=("transitive_vulnerabilities", "mean"),
        mean_transitive_deps=("transitive_dependencies", "mean"),
    ).round(2)
    print(pm_transit)
