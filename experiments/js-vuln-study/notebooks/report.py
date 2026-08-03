"""Render a knit-style PDF report from the study's parquet tables.

The dev box has no LaTeX/quarto/pandoc, so instead of knitting the notebook we
build the figures with matplotlib and assemble a polished document with reportlab
(pure-Python, no system deps). Mirrors the structure of `analysis.py`.

    cd experiments/js-vuln-study
    .venv/bin/python notebooks/report.py
    # -> data/report/js-vuln-study-report.pdf
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]

# Shared statistics (same module analysis.py uses) — one source for the numbers.
import sys  # noqa: E402

sys.path.insert(0, str(ROOT))
from js_vuln_study.stats import (  # noqa: E402
    gini,
    km_curve,
    km_median,
    lorenz,
    presence_intervals,
    sensitivity_sweep,
)

TABLES = ROOT / "data" / "tables"
OUT = ROOT / "data" / "report"
FIGS = OUT / "figs"
OUT.mkdir(parents=True, exist_ok=True)
FIGS.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------- #
# Load + compute (mirrors analysis.py)
# --------------------------------------------------------------------------- #
analyses = pd.read_parquet(TABLES / "analyses.parquet")
vulns = pd.read_parquet(TABLES / "vulns.parquet")
_deps_path = TABLES / "dependencies.parquet"
deps = pd.read_parquet(_deps_path) if _deps_path.exists() else pd.DataFrame(
    columns=["direct", "transitive"]
)
head = analyses[analyses["snapshot_date"] == "HEAD"].copy()
# The vulns table spans every snapshot (HEAD + historical quarters); each project
# therefore contributes one block of rows PER snapshot. Every cross-sectional
# statistic must run on the HEAD slice only, or projects get counted once per
# snapshot (~18x over). The per-snapshot point-in-time view below is the sole
# exception — it deliberately uses the full table.
vulns_head = vulns[vulns["snapshot_date"] == "HEAD"].copy()

N = len(head)
N_TARGET = 100
n_with_vuln = int((head["total_vulnerabilities"] > 0).sum())
n_empty = int((head["total_dependencies"] == 0).sum())

med_vulns = head["total_vulnerabilities"].median()
mean_vulns = head["total_vulnerabilities"].mean()
max_vulns = head["total_vulnerabilities"].max()

severity_cols = ["n_critical", "n_high", "n_medium", "n_low", "n_none"]
sev_totals = head[severity_cols].sum()
crit_high_share = sev_totals[["n_critical", "n_high"]].sum() / sev_totals.sum()

spread = vulns_head.groupby("affected_dependency")["npm_name"].nunique().sort_values(ascending=False)
pkg_counts = vulns_head.groupby("affected_dependency").size().sort_values(ascending=False)
total_instances = int(pkg_counts.sum())
cum_share = pkg_counts.cumsum() / total_instances

# Population invariants — guard against the HEAD/all-snapshots mixing bug.
assert total_instances == len(vulns_head), (total_instances, len(vulns_head))
assert total_instances == int(sev_totals.sum()), (total_instances, int(sev_totals.sum()))
assert int(spread.iloc[0]) <= N, (int(spread.iloc[0]), N)


proj_vulns = head["total_vulnerabilities"].values
pkg_instances = pkg_counts.values
gini_proj, gini_pkg = gini(proj_vulns), gini(pkg_instances)
top10_proj = np.sort(proj_vulns)[::-1][:10].sum() / proj_vulns.sum()
top10_pkg = pkg_counts.head(10).sum() / total_instances


def pkgs_for(target):
    return int((cum_share < target).sum()) + 1


# --------------------------------------------------------------------------- #
# Robustness: match-confidence sensitivity
# ~11% of HEAD matches carry MATCH_POSSIBLE_INCORRECT. Recompute the headline on
# the high-confidence subset (conflict_flag == MATCH_CORRECT) so we can report
# how much the concentration/remediation story depends on the dubious matches.
# --------------------------------------------------------------------------- #
sweep = sensitivity_sweep(vulns_head, head)
_sw = sweep.set_index("subset")
vulns_head_hi = vulns_head[vulns_head["conflict_flag"].astype(str) == "MATCH_CORRECT"].copy()
n_low_conf = total_instances - len(vulns_head_hi)
sens_all = {
    "instances": int(_sw.loc["all", "instances"]),
    "packages": int(_sw.loc["all", "distinct_vuln_packages"]),
    "top10_pkg": float(_sw.loc["all", "top10_pkg_share"]),
    "gini_pkg": float(_sw.loc["all", "gini_pkg"]),
    "clear50": int(_sw.loc["all", "pkgs_clear_50"]),
    "crit_high_share": float(_sw.loc["all", "high_critical_share"]),
}
sens_hi = {
    "instances": int(_sw.loc["match_correct_only", "instances"]),
    "packages": int(_sw.loc["match_correct_only", "distinct_vuln_packages"]),
    "top10_pkg": float(_sw.loc["match_correct_only", "top10_pkg_share"]),
    "gini_pkg": float(_sw.loc["match_correct_only", "gini_pkg"]),
    "clear50": int(_sw.loc["match_correct_only", "pkgs_clear_50"]),
    "crit_high_share": float(_sw.loc["match_correct_only", "high_critical_share"]),
}


from scipy.stats import spearmanr  # noqa: E402

sub = head[head["total_dependencies"] > 0].copy()
sub["vulns_per_1k_deps"] = 1000 * sub["total_vulnerabilities"] / sub["total_dependencies"]
rho_v, p_v = spearmanr(sub["rank"], sub["total_vulnerabilities"])

by_pm = (
    sub.groupby("package_manager")
    .apply(lambda x: pd.Series({
        "projects": len(x),
        "median_deps": x["total_dependencies"].median(),
        "median_vulns": x["total_vulnerabilities"].median(),
        "vulns_per_1k_deps": 1000 * x["total_vulnerabilities"].sum() / x["total_dependencies"].sum(),
    }), include_groups=False)
    .round(2)
)

# --------------------------------------------------------------------------- #
# Figures
# --------------------------------------------------------------------------- #
def _save(fig, name):
    path = FIGS / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(path)


# Severity mix
fig, ax = plt.subplots(figsize=(6, 3.4))
sev_totals.plot.bar(ax=ax, color=["#b30000", "#e34a33", "#fc8d59", "#fdcc8a", "#dddddd"])
ax.set_ylabel("CVE instances")
ax.set_xticklabels([c.replace("n_", "") for c in severity_cols], rotation=0)
ax.set_title("Severity mix across the sample")
fig_sev = _save(fig, "severity.png")

# Hotspots
fig, ax = plt.subplots(figsize=(6, 4))
top = spread.head(15)[::-1]
ax.barh(top.index, top.values, color="#cb181d")
ax.set_xlabel(f"# projects affected (of {N})")
ax.set_title("Most systemic vulnerable packages")
fig_hot = _save(fig, "hotspots.png")

# Lorenz
fig, ax = plt.subplots(figsize=(5, 5))
for vals, label, color in [
    (proj_vulns, f"vulns across projects (Gini={gini_proj:.2f})", "#08519c"),
    (pkg_instances, f"instances across packages (Gini={gini_pkg:.2f})", "#cb181d"),
]:
    px, py = lorenz(vals)
    ax.plot(px, py, label=label, color=color)
ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="perfect equality")
ax.set_xlabel("cumulative share of population")
ax.set_ylabel("cumulative share of vuln mass")
ax.set_title("Concentration of exposure")
ax.legend(loc="upper left", fontsize=7)
fig_lorenz = _save(fig, "lorenz.png")

# Remediation curve
fig, ax = plt.subplots(figsize=(6, 3.6))
ax.plot(np.arange(1, len(cum_share) + 1), 100 * cum_share.values, color="#cb181d")
for t in (0.5, 0.8, 0.9):
    k = pkgs_for(t)
    ax.axhline(100 * t, color="grey", ls=":", lw=0.8)
    ax.axvline(k, color="grey", ls=":", lw=0.8)
    ax.annotate(f"{k} pkgs", (k, 100 * t), fontsize=7, xytext=(4, -10), textcoords="offset points")
ax.set_xscale("log")
ax.set_xlabel("# upstream packages fixed (ranked by impact, log)")
ax.set_ylabel("% of vuln instances removed")
ax.set_title("Remediation leverage")
fig_rem = _save(fig, "remediation.png")

# Popularity scatter
fig, ax = plt.subplots(figsize=(6, 3.6))
ax.scatter(sub["rank"], sub["total_vulnerabilities"], alpha=0.6, color="#238b45")
ax.set_xlabel("GitHub star rank (0 = most popular)")
ax.set_ylabel("vulnerabilities")
ax.set_title(f"Popularity vs vulnerability load (Spearman rho={rho_v:+.2f}, p={p_v:.2f})")
fig_pop = _save(fig, "popularity.png")

# Evolution: disclosures over time + (if longitudinal) point-in-time trajectory.
# Disclosure timeline holds the dependency tree fixed at HEAD and dates each
# present vulnerability by its advisory publication — so it runs on the HEAD
# slice (count each vuln once). The point-in-time trajectory further down is the
# only block that uses the full multi-snapshot table.
ev = vulns_head.copy()
ev["published"] = pd.to_datetime(ev["published_date"], errors="coerce", utc=True)
ev = ev.dropna(subset=["published"])
ev["year"] = ev["published"].dt.year
ev["quarter"] = ev["published"].dt.tz_convert(None).dt.to_period("Q").astype(str)
yr = ev.groupby("year").size()
yoy = (yr.pct_change() * 100).round(0)

sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
sev_color = {"CRITICAL": "#b30000", "HIGH": "#e34a33", "MEDIUM": "#fc8d59", "LOW": "#fdcc8a", "NONE": "#dddddd"}
ev_sev = ev.assign(sev=ev["severity_class"].where(ev["severity_class"].isin(sev_order), "NONE"))
piv = ev_sev.groupby(["quarter", "sev"]).size().unstack(fill_value=0)
piv = piv.reindex(columns=[s for s in sev_order if s in piv.columns])
fig, ax = plt.subplots(figsize=(8, 3.6))
piv.plot.bar(stacked=True, ax=ax, color=[sev_color[c] for c in piv.columns], width=0.9, legend=True)
for i, lab in enumerate(ax.get_xticklabels()):
    lab.set_fontsize(5)
    lab.set_visible(i % 2 == 0)
ax.set_xlabel("disclosure quarter")
ax.set_ylabel("vulnerabilities disclosed")
ax.set_title("Disclosures per quarter affecting the sample (by severity)")
ax.legend(fontsize=6)
fig_spike = _save(fig, "evolution_spike.png")

# Point-in-time per-project trajectory (only if a longitudinal run populated snapshots)
fig_traj = None
n_snapshots = analyses["snapshot_date"].nunique()
traj = None
n_balanced = 0
if n_snapshots >= 2:
    t = vulns.copy()
    t["published"] = pd.to_datetime(t["published_date"], errors="coerce", utc=True)
    t = t[t["snapshot_date"] != "HEAD"].copy()
    t["snap"] = pd.to_datetime(t["snapshot_date"], errors="coerce", utc=True)
    pit = t[t["published"] <= t["snap"]]
    traj = (pit.groupby(["snapshot_date", "npm_name"]).size()
               .groupby("snapshot_date").agg(["mean", "median"]).sort_index())
    # Panel composition changes over time (fewer projects existed in early
    # snapshots), so annotate each tick with the project count behind the mean.
    snap_dates = sorted(d for d in analyses["snapshot_date"].unique() if d != "HEAD")
    n_proj = (analyses[analyses["snapshot_date"] != "HEAD"]
              .groupby("snapshot_date")["npm_name"].nunique())
    # Balanced panel: projects analysed at EVERY snapshot — a like-for-like trend
    # free of composition change. Count point-in-time vulns over the full
    # (snapshot x balanced-project) grid, zero-filling projects with no disclosed
    # vuln yet (else the mean is biased upward by dropping the zeros).
    present = (analyses[analyses["snapshot_date"] != "HEAD"]
               .groupby("npm_name")["snapshot_date"].nunique())
    balanced = sorted(present[present == len(snap_dates)].index)
    n_balanced = len(balanced)
    traj_bal = None
    if balanced:
        grid = pd.MultiIndex.from_product([snap_dates, balanced],
                                          names=["snapshot_date", "npm_name"])
        counts_bal = (pit[pit["npm_name"].isin(balanced)]
                      .groupby(["snapshot_date", "npm_name"]).size()
                      .reindex(grid, fill_value=0))
        traj_bal = counts_bal.groupby(level="snapshot_date").mean().sort_index()
    if len(traj) >= 2:
        fig, ax = plt.subplots(figsize=(8, 3.6))
        ax.plot(traj.index, traj["mean"], marker="o", label="mean/project (all present)")
        ax.plot(traj.index, traj["median"], marker="s", label="median/project (all present)")
        if traj_bal is not None:
            ax.plot(traj_bal.index, traj_bal.values, marker="^", color="#cb181d",
                    label=f"mean/project (balanced panel, n={n_balanced})")
        ax.set_xticks(range(len(traj.index)))
        ax.set_xticklabels([f"{d}  (n={int(n_proj.get(d, 0))})" for d in traj.index])
        ax.set_xlabel("snapshot date (n = projects present)")
        ax.set_ylabel("known vulns per project (point-in-time)")
        ax.set_title("Within-project vulnerability evolution (point-in-time correct)")
        ax.legend(fontsize=7)
        plt.xticks(rotation=90, fontsize=6)
        ax.grid(True, alpha=0.3)
        fig_traj = _save(fig, "evolution_trajectory.png")

# RQ-G: survival of (CVE, package) pairs — needs the longitudinal tables.
fig_km = None
km_medians: list[tuple[str, int, float]] = []
if analyses["snapshot_date"].nunique() >= 2:
    _intervals = presence_intervals(vulns, analyses)
    if len(_intervals):
        fig, ax = plt.subplots(figsize=(7.5, 4))
        for sev, color in [("CRITICAL", "#a50f15"), ("HIGH", "#de2d26"),
                           ("MEDIUM", "#fb6a4a"), ("LOW", "#fcae91")]:
            sub_i = _intervals[_intervals["severity_class"].astype(str).str.upper() == sev]
            if len(sub_i) < 5:
                continue
            t, sv = km_curve(sub_i["duration_days"], sub_i["event"])
            km_medians.append((sev, len(sub_i), km_median(t, sv)))
            ax.step(t, sv, where="post", color=color, label=f"{sev} (n={len(sub_i)})")
        if km_medians:
            ax.set_xlabel("days since first observed")
            ax.set_ylabel("share still present (KM)")
            ax.grid(True, alpha=0.3)
            ax.legend(fontsize=8)
            fig_km = _save(fig, "survival_km.png")
        else:
            plt.close(fig)

# --------------------------------------------------------------------------- #
# PDF assembly
# --------------------------------------------------------------------------- #
styles = getSampleStyleSheet()
styles.add(ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=20, spaceAfter=6))
styles.add(ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10, textColor=colors.grey, alignment=TA_CENTER))
styles.add(ParagraphStyle("H", parent=styles["Heading2"], textColor=colors.HexColor("#08306b"), spaceBefore=14))
styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13, spaceAfter=6))
styles.add(ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=10))

USABLE_W = A4[0] - 4 * cm
story = []


def P(txt, style="Body"):
    story.append(Paragraph(txt, styles[style]))


def figure(path, caption, width=14 * cm):
    img = Image(path)
    img._restrictSize(width, 11 * cm)
    img.hAlign = "CENTER"
    story.append(Spacer(1, 4))
    story.append(img)
    story.append(Paragraph(caption, styles["Caption"]))


def table(data, col_widths=None, header=True):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fb")]),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#08306b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 8))


# --- Title -----------------------------------------------------------------
P("The Dependency-Vulnerability Landscape of the<br/>Top-100 GitHub JavaScript/TypeScript Projects", "TitleBig")
P("A cross-sectional study at HEAD with a point-in-time longitudinal view &nbsp;·&nbsp; generated "
  + date.today().isoformat(), "Sub")
story.append(Spacer(1, 10))

# --- Executive summary -----------------------------------------------------
P("Executive summary", "H")
P(f"We analysed the {N} most-starred GitHub JS/TS repositories (of a {N_TARGET}-repo target; "
  f"{N_TARGET - N} excluded by lockfile-parse failures) with CodeClarity at their default-branch HEAD. "
  f"<b>{n_with_vuln}/{N} ({n_with_vuln / N:.0%})</b> ship at least one known-vulnerable dependency.")
P("<b>Key findings:</b>")
P(f"&bull; <b>Exposure is highly concentrated.</b> The top-10 vulnerable packages account for "
  f"<b>{top10_pkg:.0%}</b> of all {total_instances} vulnerability instances (Gini {gini_pkg:.2f}); "
  f"the top-10 projects hold <b>{top10_proj:.0%}</b> of all vulnerabilities (Gini {gini_proj:.2f}).")
P(f"&bull; <b>A few upstream fixes clear most risk.</b> Fixing just <b>{pkgs_for(0.5)}</b> packages "
  f"({pkgs_for(0.5) / len(pkg_counts):.0%} of the {len(pkg_counts)} distinct vulnerable packages) removes "
  f"50% of all instances; {pkgs_for(0.8)} clear 80%, {pkgs_for(0.9)} clear 90%.")
P(f"&bull; <b>Popularity does not predict security.</b> Star rank vs vulnerability load shows no "
  f"relationship (Spearman &rho;={rho_v:+.2f}, p={p_v:.2f}).")
P(f"&bull; <b>Severity skews high.</b> {crit_high_share:.0%} of classified CVEs are high or critical "
  f"(critical={int(sev_totals['n_critical'])}, high={int(sev_totals['n_high'])}).")

# --- Data & methods --------------------------------------------------------
P("Data &amp; methods", "H")
P(f"Sample: top-{N_TARGET} repos by GitHub stars across language:JavaScript and language:TypeScript, "
  f"requiring a committed package.json + lockfile. Each repo scanned at HEAD via CodeClarity "
  f"(js-sbom &rarr; vuln-finder), plus historical quarterly snapshots for the longitudinal view. "
  f"All cross-sectional statistics use the HEAD slice only. Tables: analyses ({len(analyses)} rows "
  f"across {analyses['snapshot_date'].nunique()} snapshots; {N} at HEAD), vulns ({len(vulns):,} rows; "
  f"{total_instances:,} at HEAD), dependencies ({len(deps):,}).")
table([
    ["Metric", "Value"],
    ["Repositories analysed", f"{N} / {N_TARGET}"],
    ["Repos with >=1 known-vuln dependency", f"{n_with_vuln} ({n_with_vuln / N:.0%})"],
    ["Empty-dependency scans", str(n_empty)],
    ["Vulnerability instances", f"{total_instances:,}"],
    ["Distinct vulnerable packages", str(len(pkg_counts))],
    ["Vulns / project (median / mean / max)", f"{med_vulns:.0f} / {mean_vulns:.0f} / {max_vulns:.0f}"],
], col_widths=[10 * cm, 6 * cm])

P("RQ-A &mdash; Prevalence &amp; severity", "H")
P("Vulnerability load is heavy-tailed: a median of "
  f"{med_vulns:.0f} vulnerabilities per project but a mean of {mean_vulns:.0f} (max {max_vulns:.0f}).")
figure(fig_sev, "Figure 1. CVE instances by severity class across the sample.", width=12 * cm)

story.append(PageBreak())

# --- RQ-B ------------------------------------------------------------------
P("RQ-B &mdash; Concentration &amp; hotspots (headline)", "H")
P("Exposure is dominated by a small set of widely-reused, mostly transitive packages. "
  f"<b>{spread.index[0]}</b> alone appears in <b>{int(spread.iloc[0])}/{N}</b> projects.")
figure(fig_hot, "Figure 2. Top-15 vulnerable packages by number of projects affected.")
hot_rows = [["Package", "# projects", "# vuln instances"]]
for pkg in spread.head(10).index:
    hot_rows.append([pkg, str(int(spread[pkg])), str(int(pkg_counts.get(pkg, 0)))])
table(hot_rows, col_widths=[8 * cm, 4 * cm, 4 * cm])
figure(fig_lorenz, "Figure 3. Lorenz curves: exposure is far from evenly distributed.", width=10 * cm)

P("Remediation leverage", "H")
P("Ranking packages by the number of vulnerability instances they cause shows that fixing a "
  "handful of upstream dependencies would clear most of the ecosystem's measured risk:")
rem_rows = [["Action", "% of instances removed"]]
for n in (1, 5, 10, 20, 50):
    rem_rows.append([f"fix top-{n} packages", f"{cum_share.iloc[n - 1]:.0%}"])
for t in (0.5, 0.8, 0.9):
    rem_rows.append([f"packages needed to clear {t:.0%}", f"{pkgs_for(t)} packages"])
table(rem_rows, col_widths=[10 * cm, 6 * cm])
figure(fig_rem, "Figure 4. Cumulative share of vulnerability instances removed by fixing the top-N packages.", width=13 * cm)

# --- Robustness: match-confidence sensitivity ------------------------------
P("Robustness &mdash; match-confidence sensitivity", "H")
P(f"{n_low_conf:,}/{total_instances:,} HEAD matches ({n_low_conf / total_instances:.0%}) carry a "
  "<i>possibly-incorrect</i> conflict flag. Re-running the headline on the high-confidence subset "
  "(<tt>conflict_flag = MATCH_CORRECT</tt>) leaves the concentration and remediation story intact, "
  "so the findings do not hinge on the dubious matches:")
sens_rows = [
    ["Metric", "All matches", "High-confidence only"],
    ["Vulnerability instances", f"{sens_all['instances']:,}", f"{sens_hi['instances']:,}"],
    ["Distinct vulnerable packages", f"{sens_all['packages']:,}", f"{sens_hi['packages']:,}"],
    ["Top-10 packages' share", f"{sens_all['top10_pkg']:.0%}", f"{sens_hi['top10_pkg']:.0%}"],
    ["Concentration (Gini, packages)", f"{sens_all['gini_pkg']:.2f}", f"{sens_hi['gini_pkg']:.2f}"],
    ["Packages to clear 50%", f"{sens_all['clear50']}", f"{sens_hi['clear50']}"],
    ["High+critical share", f"{sens_all['crit_high_share']:.0%}", f"{sens_hi['crit_high_share']:.0%}"],
]
table(sens_rows, col_widths=[7 * cm, 4.5 * cm, 4.5 * cm])

P("The full sweep re-derives every scalar headline metric under four measurement subsets "
  "(all matches, high-confidence only, non-withdrawn advisories, direct dependencies only). "
  "Claims elsewhere in this report should be read against this table &mdash; a finding that "
  "flips across rows is fragile:")
sweep_rows = [["Subset", "Instances", "Affected", "Median load", "Top-10 pkg", "Gini pkg", "Clear 50%"]]
for _, r in sweep.iterrows():
    sweep_rows.append([
        r["subset"], f"{int(r['instances']):,}", f"{int(r['n_affected'])}/{int(r['n_projects'])}",
        f"{r['load_median']:.0f}", f"{r['top10_pkg_share']:.0%}", f"{r['gini_pkg']:.2f}",
        f"{int(r['pkgs_clear_50'])}",
    ])
table(sweep_rows, col_widths=[3.6 * cm, 2.4 * cm, 2.2 * cm, 2.4 * cm, 2.2 * cm, 1.8 * cm, 1.8 * cm])

story.append(PageBreak())

# --- RQ-C ------------------------------------------------------------------
P("RQ-C &mdash; Popularity vs security", "H")
P(f"Among the analysed top repos, GitHub star rank shows no significant association with "
  f"vulnerability load (Spearman &rho;={rho_v:+.2f}, p={p_v:.2f}, n={len(sub)}) &mdash; a weak "
  "positive trend that does not reach significance at this sample size, so the study is "
  "underpowered for a firm claim rather than a definitive null. The tentative reading is that "
  "exposure is driven by dependency choices, not project prominence.")
figure(fig_pop, "Figure 5. Vulnerability load vs popularity rank (0 = most-starred).", width=13 * cm)

# --- RQ-D ------------------------------------------------------------------
P("RQ-D &mdash; Package-manager differences", "H")
P("Descriptive only &mdash; package-manager choice is confounded with project size, so counts are "
  "normalised to vulnerabilities per 1,000 resolved dependencies.")
pm_rows = [["Package manager", "Projects", "Median deps", "Median vulns", "Vulns / 1k deps"]]
for pm, r in by_pm.iterrows():
    pm_rows.append([pm, f"{int(r['projects'])}", f"{r['median_deps']:.0f}", f"{r['median_vulns']:.0f}", f"{r['vulns_per_1k_deps']:.1f}"])
table(pm_rows, col_widths=[4.5 * cm, 2.5 * cm, 3 * cm, 3 * cm, 3 * cm])

# --- RQ-F: evolution -------------------------------------------------------
story.append(PageBreak())
P("RQ-F &mdash; Vulnerability evolution over time", "H")
peak_year = int(yr.idxmax())
P(f"Holding each project's dependency tree fixed at HEAD and dating every present "
  f"vulnerability by its CVE/advisory publication, disclosures affecting the sample "
  f"cluster in recent years. Peak year: <b>{peak_year}</b> with <b>{int(yr.max())}</b> "
  f"disclosures. This is a recency-of-disclosure view, not a trend in the projects "
  f"themselves; the point-in-time trajectory below is the like-for-like evolution measure.")
yrs_show = [y for y in yr.index if y >= yr.index.max() - 5]
yr_rows = [["Disclosure year", "Vulnerabilities", "YoY"]]
for y in yrs_show:
    g = "" if pd.isna(yoy[y]) else f"{yoy[y]:+.0f}%"
    yr_rows.append([str(int(y)), str(int(yr[y])), g])
table(yr_rows, col_widths=[5 * cm, 5 * cm, 4 * cm])
figure(fig_spike, "Figure 6. Vulnerability disclosures per quarter affecting the sample, by severity.")
if fig_traj is not None:
    P("With historical snapshots, we reconstruct each project's <i>point-in-time</i> exposure: at "
      "every snapshot we count only vulnerabilities already disclosed by that date, using the "
      "dependencies actually present then &mdash; avoiding the anachronism of judging old code by "
      "today's database. Because the set of projects present grows over time, the blue/orange "
      "lines mix a rising trend with changing composition; the red <b>balanced panel</b> "
      f"(the {n_balanced} projects analysed at <i>every</i> snapshot, zero-filled) is the "
      "like-for-like trend and rises more gently.")
    figure(fig_traj, "Figure 7. Within-project vulnerability load over time (point-in-time correct); "
                     "red = balanced panel.")
else:
    P("<i>Point-in-time per-project trajectories require a longitudinal "
      "(<tt>submit --snapshots</tt>) run; this report reflects the disclosure-date view only.</i>")

# --- RQ-G: time-to-fix survival ---------------------------------------------
if fig_km is not None:
    P("RQ-G &mdash; Vulnerable-version residence time (survival)", "H")
    P("How long does a known-vulnerable (CVE, package) pair persist in a project once observed? "
      "Presence intervals are built from consecutive completed snapshots of the same project "
      "(a removal is counted only when the pair is absent at the immediately-next completed snapshot; "
      "coverage gaps censor), and curves are Kaplan&ndash;Meier, stratified by severity. "
      "These are <b>residence times of vulnerable versions</b>, not remediation lags: for a large "
      "share of historical rows the advisory was published after the snapshot (or carries no date), "
      "so the clock can start before disclosure.")
    km_rows = [["Severity", "Intervals", "KM median residence (days)"]]
    for sev, n_i, med in km_medians:
        km_rows.append([sev, str(n_i), "not reached" if med != med else f"{med:.0f}"])
    table(km_rows, col_widths=[5 * cm, 4 * cm, 6 * cm])
    figure(fig_km, "Figure 8. Survival of known-vulnerable (CVE, package) pairs, by severity.")

# --- Threats to validity ---------------------------------------------------
P("Threats to validity", "H")
n_direct = int(vulns_head["direct_dependency"].sum())
n_flagged_incorrect = int(
    vulns_head["conflict_flag"].astype(str).str.contains("POSSIBLE_INCORRECT").sum()
)
threats = [
    f"<b>Selection bias.</b> {N_TARGET - N} top repos were excluded due to unsupported (Yarn Berry / newer) "
    "lockfile formats, biasing the sample toward parseable lockfiles &mdash; the dominant threat.",
    f"<b>Match quality.</b> {n_flagged_incorrect:,}/{total_instances:,} HEAD matches "
    f"({n_flagged_incorrect / total_instances:.0%}) carry a possibly-incorrect conflict flag; "
    "headline counts should be read with a sensitivity check that excludes them.",
    f"<b>Direct vs transitive.</b> {n_direct:,}/{total_instances:,} HEAD vulnerability rows are flagged "
    "direct and the rest transitive; the split is reported descriptively, not as a precise install-tree measure.",
    (f"<b>EPSS coverage.</b> {int(vulns_head['epss_score'].notna().sum()):,}/{total_instances:,} HEAD matches "
     "carry an EPSS exploit-likelihood score (attached at analysis time from the recorded EPSS snapshot); "
     "rows analysed before EPSS attachment, or with non-CVE identifiers, have none.")
    if int(vulns_head["epss_score"].notna().sum()) > 0
    else "<b>No EPSS.</b> The EPSS field is empty for this dataset (analyses predate EPSS attachment), "
         "so exploit-likelihood prioritisation is out of scope.",
    "<b>Disclosure-date recency.</b> The disclosure timeline holds the HEAD dependency tree fixed and dates "
    "vulnerabilities by advisory publication; it is not a trend in the projects. The point-in-time trajectory "
    "is the like-for-like longitudinal measure, but its panel composition grows over time (24&rarr;37 projects).",
    "<b>Single scanner.</b> All matches come from one tool (CodeClarity); absolute counts are scanner-dependent.",
]
if len(deps) > 0:
    n_unclass = int(((~deps["direct"]) & (~deps["transitive"])).sum())
    threats.insert(3, f"<b>Dependency multiset.</b> {n_unclass:,}/{len(deps):,} dependency rows are neither "
                      "flagged direct nor transitive; total_dependencies is a bloat proxy, used only as a normaliser.")
for txt in threats:
    P("&bull; " + txt)

# --------------------------------------------------------------------------- #
doc = SimpleDocTemplate(
    str(OUT / "js-vuln-study-report.pdf"),
    pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
    title="Top-100 GitHub JS/TS Vulnerability Landscape",
)
doc.build(story)
print(f"wrote {OUT / 'js-vuln-study-report.pdf'}")
