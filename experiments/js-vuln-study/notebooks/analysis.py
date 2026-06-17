# ruff: noqa: E402
"""Analysis notebook for the top-100 GitHub JS/TS vulnerability study.

Each `# %%` block is a cell — open in VS Code / Jupyter and "Run Current Cell",
or run the whole thing top-to-bottom:

    cd experiments/js-vuln-study
    MPLBACKEND=Agg .venv/bin/python notebooks/analysis.py

It drives the three parquet tables produced by `python run.py collect`:

    data/tables/analyses.parquet       # one row per (project, snapshot) scan
    data/tables/vulns.parquet          # one row per (analysis, vulnerability)
    data/tables/dependencies.parquet   # one row per (analysis, dependency)

This is a CROSS-SECTIONAL measurement study of the 100 most-starred GitHub
JavaScript/TypeScript repositories at HEAD. The sample is single-tier (top-100)
and single-snapshot (HEAD), so the analysis focuses on what that supports:

    RQ-A  Prevalence & severity of known-vulnerable dependencies
    RQ-B  Concentration & hotspots  — the headline: a few transitive packages
          drive most of the ecosystem's exposure
    RQ-C  Popularity vs security    — does star rank predict vuln load? (null)
    RQ-D  Package-manager differences in dependency bloat & vuln density
    RQ-E  Measurement caveats / threats to validity

The data is heavy-tailed, so we lead with medians/IQR, ECDFs and log scales
rather than means. Cells degrade gracefully when a column is empty.
"""

# %% [markdown]
# # 0. Setup, helpers, and data-quality preamble

# %%
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "tables"

analyses = pd.read_parquet(DATA_DIR / "analyses.parquet")
vulns = pd.read_parquet(DATA_DIR / "vulns.parquet")
# The per-dependency table is optional — the longitudinal run is collected with
# `--no-deps` (it would be tens of millions of rows). Fall back to an empty frame
# with the expected columns so dep-dependent cells degrade gracefully.
_deps_path = DATA_DIR / "dependencies.parquet"
if _deps_path.exists():
    deps = pd.read_parquet(_deps_path)
else:
    deps = pd.DataFrame(columns=["direct", "transitive", "name", "package_manager"])
    print("(no dependencies.parquet — collected with --no-deps; dep-level cells skipped)")

# HEAD-only study; keep the filter explicit so the notebook still does the right
# thing if longitudinal snapshots are added later.
head = analyses[analyses["snapshot_date"] == "HEAD"].copy()
# The vulns table spans every snapshot (HEAD + historical quarters), so each
# project contributes one block of rows per snapshot. ALL cross-sectional stats
# (RQ-A/B/C/D and the disclosure timeline) must run on this HEAD slice, or
# projects get counted once per snapshot (~18x over). The only exception is the
# point-in-time per-project trajectory (RQ-F), which deliberately uses every
# snapshot — it is the one block left on the full `vulns` frame.
vulns_head = vulns[vulns["snapshot_date"] == "HEAD"].copy()

print("analyses:", analyses.shape, "| HEAD rows:", head.shape[0])
print("vulns:   ", vulns.shape, "| HEAD vuln rows:", vulns_head.shape[0])
print("deps:    ", deps.shape)
# Population invariant: HEAD vuln rows must equal the summed per-project counts.
assert len(vulns_head) == int(head[["n_critical", "n_high", "n_medium", "n_low", "n_none"]].sum().sum())


# %%
# --- small, dependency-free statistical helpers -----------------------------

def gini(x):
    """Gini coefficient of a non-negative array (0 = equal, →1 = concentrated)."""
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    if x.size == 0 or np.all(x == 0):
        return float("nan")
    x = np.sort(x)
    n = x.size
    cum = np.cumsum(x)
    # Mean absolute difference formulation.
    return float((2.0 * np.sum((np.arange(1, n + 1)) * x) - (n + 1) * cum[-1]) / (n * cum[-1]))


def lorenz(x):
    """Return (population_share, value_share) points for a Lorenz curve."""
    x = np.sort(np.asarray(x, dtype=float))
    x = x[~np.isnan(x)]
    cum = np.cumsum(x)
    cum = np.insert(cum, 0, 0)
    pop = np.linspace(0.0, 1.0, cum.size)
    val = cum / cum[-1] if cum[-1] > 0 else np.zeros_like(cum)
    return pop, val


def ecdf(x):
    """Return (sorted_values, cumulative_probability) for an empirical CDF."""
    x = np.sort(np.asarray(x, dtype=float))
    y = np.arange(1, x.size + 1) / x.size
    return x, y


def pairwise_mwu(groups: dict):
    """Bonferroni-corrected Mann–Whitney U posthoc across named groups.

    `groups` maps label -> 1d array. Returns a tidy DataFrame of pairwise
    comparisons. Avoids a scikit-posthocs dependency.
    """
    from itertools import combinations

    from scipy.stats import mannwhitneyu

    labels = [k for k, v in groups.items() if len(v) > 1]
    pairs = list(combinations(labels, 2))
    m = max(len(pairs), 1)
    rows = []
    for a, b in pairs:
        try:
            u, p = mannwhitneyu(groups[a], groups[b], alternative="two-sided")
        except ValueError:
            u, p = float("nan"), float("nan")
        rows.append({
            "a": a, "b": b,
            "median_a": float(np.median(groups[a])),
            "median_b": float(np.median(groups[b])),
            "p_raw": p,
            "p_bonferroni": min(p * m, 1.0) if p == p else p,
        })
    return pd.DataFrame(rows)


# %% [markdown]
# ## Data quality & threats to validity — read this first
#
# The numbers below are honest about the measurement pipeline's limits. Key
# caveats that shape interpretation of every later cell:
#
# * **Cross-sectional, HEAD only.** No longitudinal/evolution claims.
# * **Lockfile-parse selection bias.** Several top repos (Yarn Berry / newer
#   lockfile formats) failed SBOM generation and are absent — the sample skews
#   toward repos with parseable lockfiles.
# * **Direct/transitive split is unreliable.** Every vulnerability row is flagged
#   `transitive` even though thousands of direct deps exist — almost certainly a
#   vuln-finder flagging artifact, not a real "100% transitive" finding. We do
#   NOT draw conclusions from the direct/transitive vuln split.
# * **`total_dependencies` = full resolved version multiset.** Most dep rows are
#   neither flagged direct nor transitive, so this counts every resolved
#   package-version, not the active install tree. It is a *bloat* proxy; we say so
#   wherever it is used as a denominator.
# * **No EPSS, no source-winner.** `epss_score` and `winning_source` are empty,
#   so exploit-likelihood prioritisation is out of scope here.

# %%
n_total_target = 100
n_analyzed = head.shape[0]
n_empty = int((head["total_dependencies"] == 0).sum())
n_with_vuln = int((head["total_vulnerabilities"] > 0).sum())

print(f"Coverage: {n_analyzed}/{n_total_target} repos analyzed "
      f"({n_total_target - n_analyzed} excluded — mostly Yarn-Berry lockfile-parse failures)")
print(f"Empty-dependency scans: {n_empty}")
print(f"Repos shipping >=1 known-vulnerable dependency: {n_with_vuln}/{n_analyzed} "
      f"({n_with_vuln / n_analyzed:.0%})")

print("\nDependency-flag coverage (illustrates the 'multiset' caveat):")
print(f"  dep rows total : {len(deps):,}")
print(f"  flagged direct : {int(deps['direct'].sum()):,}")
print(f"  flagged transit: {int(deps['transitive'].sum()):,}")
print(f"  flagged neither: {int(((~deps['direct']) & (~deps['transitive'])).sum()):,}")

print("\nVuln direct/transitive flag (HEAD slice):")
print(vulns_head["direct_dependency"].value_counts(dropna=False).to_dict())
print("EPSS populated:", int(vulns_head["epss_score"].notna().sum()),
      "| winning_source populated:", int(vulns_head["winning_source"].notna().sum()))


# %% [markdown]
# # RQ-A — Prevalence & severity
# How much known-vulnerable dependency exposure do the most popular JS/TS
# projects carry at HEAD, and how severe is it?

# %%
# Distribution is heavy-tailed: report median/IQR, not just the mean.
desc = head["total_vulnerabilities"].describe(percentiles=[0.25, 0.5, 0.75, 0.9, 0.99])
print("Vulnerabilities per project:")
print(desc.round(1))
print(f"\nmedian={head['total_vulnerabilities'].median():.0f}  "
      f"mean={head['total_vulnerabilities'].mean():.1f}  "
      f"max={head['total_vulnerabilities'].max():.0f}  "
      f"(mean >> median → heavy tail)")

# %%
# ECDF of vulnerabilities per project — the honest distribution view.
x, y = ecdf(head["total_vulnerabilities"].values)
fig, ax = plt.subplots(figsize=(6, 4))
ax.step(np.maximum(x, 0.5), y, where="post")
ax.set_xscale("log")
ax.set_xlabel("vulnerabilities per project (log)")
ax.set_ylabel("cumulative fraction of projects")
ax.set_title("RQ-A: ECDF of vulnerability load (top-100 GitHub JS/TS, HEAD)")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# %%
# Severity mix — count of CVE instances by CVSS class across the whole sample.
severity_cols = ["n_critical", "n_high", "n_medium", "n_low", "n_none"]
totals = head[severity_cols].sum()
print("Severity mix (CVE instances):")
print(totals.to_dict())
if totals.sum() > 0:
    crit_high = totals[["n_critical", "n_high"]].sum() / totals.sum()
    print(f"critical+high share: {crit_high:.1%}")
    fig, ax = plt.subplots(figsize=(6, 4))
    totals.plot.bar(ax=ax, color=["#b30000", "#e34a33", "#fc8d59", "#fdcc8a", "#dddddd"])
    ax.set_ylabel("CVE instances (HEAD)")
    ax.set_title("RQ-A: severity mix across the sample")
    ax.set_xticklabels([c.replace("n_", "") for c in severity_cols], rotation=0)
    plt.tight_layout()
    plt.show()

# %%
# CVSS base-score distribution (severity_score is fully populated).
if vulns["severity_score"].notna().any():
    s = vulns["severity_score"].dropna()
    print(f"CVSS base score: median={s.median():.1f}  mean={s.mean():.1f}  n={len(s)}")
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(s, bins=np.arange(0, 10.5, 0.5), color="#3690c0", edgecolor="white")
    ax.set_xlabel("CVSS base score")
    ax.set_ylabel("CVE instances")
    ax.set_title("RQ-A: CVSS base-score distribution")
    plt.tight_layout()
    plt.show()


# %% [markdown]
# # RQ-B — Concentration & hotspots  (HEADLINE)
# Is exposure spread evenly, or driven by a small set of widely-reused
# dependencies? This is the paper's central supply-chain-risk result.

# %%
# Top vulnerable packages by the number of distinct projects they affect.
# This is the systemic-risk figure: one bad transitive dep => many projects.
TOPN = 15
spread = (
    vulns_head.groupby("affected_dependency")["npm_name"].nunique()
    .sort_values(ascending=False)
)
print(f"Top {TOPN} vulnerable packages by # projects affected (of {n_analyzed}):")
print(spread.head(TOPN))

fig, ax = plt.subplots(figsize=(7, 5))
top = spread.head(TOPN)[::-1]
ax.barh(top.index, top.values, color="#cb181d")
ax.set_xlabel(f"# projects affected (of {n_analyzed})")
ax.set_title("RQ-B: most systemic vulnerable packages")
ax.grid(True, axis="x", alpha=0.3)
plt.tight_layout()
plt.show()

# %%
# The single most widespread (package, CVE) pairs — concrete shared exposure.
pair = (
    vulns_head.groupby(["affected_dependency", "vulnerability_id"])["npm_name"].nunique()
    .sort_values(ascending=False)
    .head(10)
    .rename("n_projects")
)
print("Most widespread (package, CVE):")
print(pair)

# Shared *version*: how many projects ship the exact same vulnerable artifact.
shared_ver = (
    vulns_head.groupby(["affected_dependency", "affected_version"])["npm_name"].nunique()
    .sort_values(ascending=False)
    .head(10)
    .rename("n_projects")
)
print("\nMost widely-shared vulnerable (package, version):")
print(shared_ver)

# %%
# Concentration metrics — how unequal is the exposure?
proj_vulns = head["total_vulnerabilities"].values
pkg_instances = vulns_head.groupby("affected_dependency").size().values

top10_proj = np.sort(proj_vulns)[::-1][:10].sum() / max(proj_vulns.sum(), 1)
top10_pkg = np.sort(pkg_instances)[::-1][:10].sum() / max(pkg_instances.sum(), 1)
print(f"Top-10 projects hold {top10_proj:.1%} of all vulnerabilities  (Gini={gini(proj_vulns):.3f})")
print(f"Top-10 packages cause {top10_pkg:.1%} of all vuln instances    (Gini={gini(pkg_instances):.3f})")

# Lorenz curves for both distributions.
fig, ax = plt.subplots(figsize=(6, 6))
for vals, label, color in [
    (proj_vulns, "vulns across projects", "#08519c"),
    (pkg_instances, "instances across packages", "#cb181d"),
]:
    px, py = lorenz(vals)
    ax.plot(px, py, label=f"{label} (Gini={gini(vals):.2f})", color=color)
ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="perfect equality")
ax.set_xlabel("cumulative share of population")
ax.set_ylabel("cumulative share of vulnerability mass")
ax.set_title("RQ-B: concentration of vulnerability exposure")
ax.legend(loc="upper left", fontsize=8)
plt.tight_layout()
plt.show()


# %% [markdown]
# ## RQ-B (remediation): how few upstream fixes would clear most exposure?
# The actionable corollary of the concentration result. Rank packages by the
# number of vulnerability instances they account for and ask what cumulative
# share the top-N cover — i.e. the leverage of fixing a few shared dependencies.

# %%
pkg_counts = vulns_head.groupby("affected_dependency").size().sort_values(ascending=False)
total_instances = int(pkg_counts.sum())
cum_share = pkg_counts.cumsum() / total_instances

print(f"{len(pkg_counts)} distinct vulnerable packages account for "
      f"{total_instances} vulnerability instances.\n")
for n in [1, 5, 10, 20, 50]:
    if n <= len(pkg_counts):
        print(f"  fixing the top-{n:>2} packages -> removes {cum_share.iloc[n - 1]:5.1%} of all instances")

print()
for target in [0.5, 0.8, 0.9]:
    k = int((cum_share < target).sum()) + 1
    print(f"  packages needed to clear {target:.0%} of instances: {k} "
          f"({k / len(pkg_counts):.1%} of distinct vulnerable packages)")

# Coverage in project terms: how many distinct projects does the top-N footprint touch?
top10_pkgs = pkg_counts.head(10).index
proj_touched = vulns_head[vulns_head["affected_dependency"].isin(top10_pkgs)]["npm_name"].nunique()
print(f"\n  the top-10 packages alone appear in {proj_touched}/{n_analyzed} projects")

# %% [markdown]
# ## RQ-B (robustness): match-confidence sensitivity
# ~11% of HEAD matches are flagged MATCH_POSSIBLE_INCORRECT. Recompute the
# headline on the high-confidence subset and confirm the story is stable.

# %%
def headline(vdf):
    pc = vdf.groupby("affected_dependency").size().sort_values(ascending=False)
    tot = int(pc.sum())
    cum = pc.cumsum() / tot if tot else pc.cumsum()
    sev = vdf["severity_class"].str.upper().value_counts()
    return {
        "instances": tot,
        "packages": int(vdf["affected_dependency"].nunique()),
        "top10_pkg_share": (pc.head(10).sum() / tot) if tot else float("nan"),
        "gini_pkg": gini(pc.values) if tot else float("nan"),
        "clear50": (int((cum < 0.5).sum()) + 1) if tot else 0,
        "crit_high_share": ((sev.get("CRITICAL", 0) + sev.get("HIGH", 0)) / tot) if tot else float("nan"),
    }


vulns_head_hi = vulns_head[vulns_head["conflict_flag"].astype(str) == "MATCH_CORRECT"]
sens = pd.DataFrame({
    "all_matches": headline(vulns_head),
    "high_confidence": headline(vulns_head_hi),
})
print(f"Low-confidence HEAD matches excluded: {len(vulns_head) - len(vulns_head_hi)}/{len(vulns_head)} "
      f"({1 - len(vulns_head_hi) / len(vulns_head):.0%})")
print(sens.round(3).to_string())

# %%
# Cumulative remediation curve — few fixes, most of the exposure.
fig, ax = plt.subplots(figsize=(6, 4))
ax.plot(np.arange(1, len(cum_share) + 1), 100 * cum_share.values, color="#cb181d")
for target in [0.5, 0.8, 0.9]:
    k = int((cum_share < target).sum()) + 1
    ax.axhline(100 * target, color="grey", ls=":", lw=0.8)
    ax.axvline(k, color="grey", ls=":", lw=0.8)
    ax.annotate(f"{k} pkgs → {target:.0%}", (k, 100 * target),
                fontsize=8, xytext=(4, -10), textcoords="offset points")
ax.set_xscale("log")
ax.set_xlabel("# upstream packages fixed (ranked by impact, log)")
ax.set_ylabel("% of all vuln instances removed")
ax.set_title("RQ-B: remediation leverage — a few fixes clear most exposure")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()


# %% [markdown]
# # RQ-C — Popularity vs security  (null result)
# Among the 100 most-popular projects, does star rank predict vulnerability
# load? `rank` is the 0-based GitHub-star rank (0 = most-starred).

# %%
from scipy.stats import spearmanr

sub = head[head["total_dependencies"] > 0].copy()
sub["vulns_per_1k_deps"] = 1000 * sub["total_vulnerabilities"] / sub["total_dependencies"]

for col, label in [
    ("total_vulnerabilities", "total vulnerabilities"),
    ("total_dependencies", "total dependencies (bloat proxy)"),
    ("vulns_per_1k_deps", "vulns per 1k deps"),
]:
    rho, p = spearmanr(sub["rank"], sub[col])
    verdict = "no significant relationship" if p > 0.05 else "significant"
    print(f"rank vs {label:32s}: Spearman rho={rho:+.3f}  p={p:.3f}  -> {verdict}")

# %%
fig, axes = plt.subplots(1, 2, figsize=(11, 4))
for ax, col, ttl in [
    (axes[0], "total_vulnerabilities", "vulnerabilities"),
    (axes[1], "vulns_per_1k_deps", "vulns per 1k deps"),
]:
    ax.scatter(sub["rank"], sub[col], alpha=0.6, color="#238b45")
    ax.set_xlabel("GitHub star rank (0 = most popular)")
    ax.set_ylabel(ttl)
    rho, p = spearmanr(sub["rank"], sub[col])
    ax.set_title(f"{ttl}  (rho={rho:+.2f}, p={p:.2f})")
    ax.grid(True, alpha=0.3)
fig.suptitle("RQ-C: popularity does not predict vulnerability load", y=1.02)
plt.tight_layout()
plt.show()


# %% [markdown]
# # RQ-D — Package-manager differences  (supporting)
# Do npm / pnpm / yarn projects differ in dependency bloat and vulnerability
# density? CONFOUNDER: package-manager choice correlates with project size, so
# we normalise (vulns per 1k deps) and report it as descriptive, not causal.

# %%
by_pm = sub.groupby("package_manager").apply(
    lambda x: pd.Series({
        "n": len(x),
        "median_deps": x["total_dependencies"].median(),
        "median_vulns": x["total_vulnerabilities"].median(),
        "vulns_per_1k_deps": 1000 * x["total_vulnerabilities"].sum() / x["total_dependencies"].sum(),
    }),
    include_groups=False,
).round(2)
print(by_pm)

# %%
# Kruskal–Wallis across PMs on normalised density, with Bonferroni MWU posthoc.
from scipy.stats import kruskal

pm_groups = {
    pm: g["vulns_per_1k_deps"].values
    for pm, g in sub.groupby("package_manager") if len(g) > 1
}
if len(pm_groups) >= 2:
    H, p = kruskal(*pm_groups.values())
    print(f"Kruskal–Wallis (vulns per 1k deps across PMs): H={H:.3f}  p={p:.4f}")
    print("\nPairwise Mann–Whitney (Bonferroni):")
    print(pairwise_mwu(pm_groups).round(4).to_string(index=False))

# %%
# Box plot of normalised density by PM (log scale — heavy tails).
order = [pm for pm in ["NPM", "PNPM", "YARN"] if pm in pm_groups]
if order:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.boxplot([pm_groups[pm] for pm in order], showfliers=True)
    ax.set_xticklabels(order)
    ax.set_yscale("log")
    ax.set_ylabel("vulns per 1k deps (log)")
    ax.set_title("RQ-D: normalised vulnerability density by package manager")
    ax.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.show()

# %%
# Dependency bloat: direct -> transitive amplification, by PM. Uses the FLAGGED
# direct/transitive counts (not the multiset), which are the reliable ones here.
amp = head[head["direct_dependencies"] > 0].copy()
amp["amplification"] = amp["transitive_dependencies"] / amp["direct_dependencies"]
print("Transitive/direct amplification (median) by PM:")
print(amp.groupby("package_manager")["amplification"].median().round(1))
print(f"\nOverall: median {amp['amplification'].median():.1f}x "
      f"(a handful of direct deps pull in an order of magnitude more transitively)")


# %% [markdown]
# # RQ-E — Measurement caveats & data quality
# Quantifying how much to trust the vulnerability matches themselves.

# %%
# Source agreement: how often is a match flagged possibly-incorrect, and is that
# bias severity-dependent?
if vulns_head["conflict_flag"].notna().any():
    crosstab = pd.crosstab(vulns_head["conflict_flag"], vulns_head["severity_class"], margins=True)
    print("conflict_flag x severity_class (HEAD):")
    print(crosstab)
    possibly = vulns_head["conflict_flag"].astype(str).str.contains("POSSIBLE_INCORRECT").mean()
    print(f"\nShare of matches flagged possibly-incorrect: {possibly:.1%}")
else:
    print("no conflict_flag data")

# %%
# Restate the structural limitations as a checklist for the 'threats to validity'
# section of the writeup.
print("Threats to validity:")
print(f"  * Coverage: {n_analyzed}/100 repos; {100 - n_analyzed} excluded (lockfile-parse failures) -> selection bias")
_n_direct = int(vulns_head["direct_dependency"].sum())
print(f"  * Direct/transitive: {_n_direct:,}/{len(vulns_head):,} HEAD rows flagged direct -> reported descriptively only")
print(f"  * Match quality: {int(vulns_head['conflict_flag'].astype(str).str.contains('POSSIBLE_INCORRECT').sum()):,}"
      f"/{len(vulns_head):,} HEAD matches flagged possibly-incorrect -> run a sensitivity check excluding them")
print("  * EPSS / source-winner empty -> no exploit-likelihood prioritisation")
print("  * Evolution (RQ-F) disclosure timeline uses CVE dates with deps fixed at HEAD (recency bias);")
print("    the point-in-time trajectory is like-for-like but its panel grows 24->37 projects over time")


# %% [markdown]
# # RQ-F — Vulnerability evolution over time
# When were the vulnerabilities affecting the top-100 disclosed? This uses the
# CVE/advisory **publication date** (from NVDMatch/OSVMatch). Two views:
#  * **Disclosure timeline** (works on HEAD data): holds the dependency tree fixed
#    at today and asks when each present vulnerability was *first disclosed* — the
#    "vulnerabilities-found-over-time" curve and the recent spike.
#  * **Point-in-time per-project trajectories** (needs `submit --snapshots`): at
#    each snapshot, counts vulns in that snapshot's deps already disclosed by then.

# %%
# HEAD slice: deps fixed at today, each present vulnerability dated once by its
# advisory publication. (Counting on the full multi-snapshot table would tally
# each vuln once per snapshot and manufacture a spurious recent "surge".)
ev = vulns_head.copy()
ev["published"] = pd.to_datetime(ev["published_date"], errors="coerce", utc=True)
ev = ev.dropna(subset=["published"])
ev["quarter"] = ev["published"].dt.tz_convert(None).dt.to_period("Q")
ev["year"] = ev["published"].dt.year
print(f"vulns with a disclosure date: {len(ev)}/{len(vulns_head)} "
      f"({ev['published'].dt.year.min():.0f}–{ev['published'].dt.year.max():.0f})")

# Year-over-year disclosure counts + growth — the headline signal.
yr = ev.groupby("year").size()
yoy = (yr.pct_change() * 100).round(0)
print("\nvulnerabilities by disclosure YEAR (deps fixed at HEAD):")
for y in yr.index:
    g = "" if pd.isna(yoy[y]) else f"  ({yoy[y]:+.0f}% YoY)"
    print(f"  {int(y)}: {yr[y]:>5}{g}")

# %%
# Disclosures per quarter, stacked by severity — the spike, with severity context.
sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
sev_color = {"CRITICAL": "#b30000", "HIGH": "#e34a33", "MEDIUM": "#fc8d59", "LOW": "#fdcc8a", "NONE": "#dddddd"}
ev_sev = ev.assign(sev=ev["severity_class"].where(ev["severity_class"].isin(sev_order), "NONE"))
piv = ev_sev.groupby(["quarter", "sev"]).size().unstack(fill_value=0)
piv = piv.reindex(columns=[s for s in sev_order if s in piv.columns])
piv.index = piv.index.astype(str)
fig, ax = plt.subplots(figsize=(10, 4))
piv.plot.bar(stacked=True, ax=ax, color=[sev_color[c] for c in piv.columns], width=0.9)
ax.set_xlabel("disclosure quarter")
ax.set_ylabel("vulnerabilities disclosed")
ax.set_title("RQ-F: disclosures per quarter affecting today's top-100 (by severity)")
for i, lab in enumerate(ax.get_xticklabels()):
    lab.set_fontsize(6)
    lab.set_visible(i % 2 == 0)
ax.legend(fontsize=7)
plt.tight_layout()
plt.show()

# %%
# Cumulative known-vulnerability exposure over time (deps fixed at HEAD).
cum = ev.groupby("quarter").size().sort_index().cumsum()
cum.index = cum.index.astype(str)
fig, ax = plt.subplots(figsize=(9, 4))
ax.plot(range(len(cum)), cum.values, marker=".", color="#08519c")
step = max(1, len(cum) // 12)
ax.set_xticks(range(0, len(cum), step))
ax.set_xticklabels([cum.index[i] for i in range(0, len(cum), step)], rotation=90, fontsize=7)
ax.set_ylabel("cumulative vulnerabilities (disclosed ≤ date)")
ax.set_title("RQ-F: cumulative known-vulnerability exposure of today's top-100")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# %%
# Hotspot emergence — when the most systemic packages' vulns were disclosed.
TOPK = 8
top_pkgs = ev.groupby("affected_dependency")["npm_name"].nunique().sort_values(ascending=False).head(TOPK).index
emerge = ev[ev["affected_dependency"].isin(top_pkgs)]
tab = emerge.groupby(["year", "affected_dependency"]).size().unstack(fill_value=0)
print("Disclosures per year for the top systemic packages:")
print(tab.to_string())

# %%
# Point-in-time per-project trajectories — only meaningful with a longitudinal run.
if analyses["snapshot_date"].nunique() < 2:
    print("HEAD-only data: run `python run.py submit --snapshots` (and re-collect) to")
    print("populate point-in-time per-project trajectories here.")
else:
    # Each vuln row is tagged with its analysis snapshot_date; keep only those
    # disclosed on/before that snapshot (point-in-time correctness), then average
    # the per-project count across projects at each snapshot.
    t = vulns.copy()
    t["published"] = pd.to_datetime(t["published_date"], errors="coerce", utc=True)
    t = t[t["snapshot_date"] != "HEAD"].copy()
    t["snap"] = pd.to_datetime(t["snapshot_date"], errors="coerce", utc=True)
    pit = t[t["published"] <= t["snap"]]
    per = (pit.groupby(["snapshot_date", "npm_name"]).size()
              .groupby("snapshot_date").agg(["mean", "median", "sum"]))
    per = per.sort_index()
    print("Point-in-time vulnerabilities per project, by snapshot:")
    print(per.round(1).to_string())
    # Balanced panel: projects analysed at EVERY snapshot — the like-for-like
    # trend free of the composition change that inflates the all-projects mean.
    # Zero-fill projects present-but-not-yet-vulnerable at a snapshot.
    snap_dates = sorted(d for d in analyses["snapshot_date"].unique() if d != "HEAD")
    present = (analyses[analyses["snapshot_date"] != "HEAD"]
               .groupby("npm_name")["snapshot_date"].nunique())
    balanced = sorted(present[present == len(snap_dates)].index)
    print(f"\nBalanced panel: {len(balanced)} projects analysed at all {len(snap_dates)} snapshots")
    per_bal = None
    if balanced:
        grid = pd.MultiIndex.from_product([snap_dates, balanced], names=["snapshot_date", "npm_name"])
        per_bal = (pit[pit["npm_name"].isin(balanced)]
                   .groupby(["snapshot_date", "npm_name"]).size()
                   .reindex(grid, fill_value=0).groupby(level="snapshot_date").mean().sort_index())
        print("Balanced-panel mean vulns/project, by snapshot:")
        print(per_bal.round(1).to_string())
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.plot(per.index, per["mean"], marker="o", label="mean/project (all present)")
    ax.plot(per.index, per["median"], marker="s", label="median/project (all present)")
    if per_bal is not None:
        ax.plot(per_bal.index, per_bal.values, marker="^", color="#cb181d",
                label=f"mean/project (balanced panel, n={len(balanced)})")
    ax.set_xlabel("snapshot date")
    ax.set_ylabel("known vulns per project (point-in-time)")
    ax.set_title("RQ-F: within-project vulnerability evolution (point-in-time correct)")
    ax.legend()
    plt.xticks(rotation=90, fontsize=7)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()
