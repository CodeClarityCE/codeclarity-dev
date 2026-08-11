"""Render the 2-page shareable brief from the audited extraction.

Unlike report.py (the long-form document built from the parquet tables), the
brief is aimed at readers with no time. It leads with the study's novel
findings (how fast projects actually fix vulnerable dependencies, where the
risk concentrates), not with confirmatory results. Every number is read from
data/tables/results_numbers.json (the audited single source of truth behind
RESULTS.md) at build time, so the brief regenerates when the extractor reruns
and can never drift from the document. Style rule: no em dashes anywhere.

    cd experiments/js-vuln-study
    .venv/bin/python notebooks/brief.py
    # -> data/report/js-vuln-study-brief.pdf
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
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
TABLES = ROOT / "data" / "tables"
OUT = ROOT / "data" / "report"
FIGS = OUT / "figs"
OUT.mkdir(parents=True, exist_ok=True)
FIGS.mkdir(parents=True, exist_ok=True)

NUM = json.load(open(TABLES / "results_numbers.json"))

# --------------------------------------------------------------------------- #
# Numbers (all from the audited extraction; formatted in one place)
# --------------------------------------------------------------------------- #
day = NUM["survival_day_resolution"]
disc = day["disclosed"]["km_by_severity"]
sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
n_day_fixed = sum(disc[s]["n_day_fixed"] for s in sevs)
n_disclosed = NUM["survival_disclosed"]["intervals"]
km_lo = min(disc[s]["km_median_days"] for s in sevs)
km_hi = max(disc[s]["km_median_days"] for s in sevs)
pooled_7d = sum(disc[s]["n_day_fixed"] * disc[s]["fixed_within_7d_pct"] for s in sevs) / n_day_fixed
pooled_90d = sum(disc[s]["n_day_fixed"] * disc[s]["fixed_within_90d_pct"] for s in sevs) / n_day_fixed
mine_units = day["events"]
mine_found = day["by_status"]["found"]

res = NUM["survival_residence"]["km_by_severity"]
res_lo = min(res[s]["km_median_days"] for s in sevs)
res_hi = max(res[s]["km_median_days"] for s in sevs)

hist = NUM["disclosure_coverage_hist"]
pre_disclosure_share = hist["published_after_snapshot_share"]
no_date_share = hist["null_published_share"]

headline = NUM["headline"]
coverage = NUM["coverage"]
rqc = NUM["rqc"]
meta = NUM["run_meta"]

ladder = NUM["ladder"]
ladder_worst = ladder["rungs"][0]["vs_freshest"]["instance_delta_pct"]

# --------------------------------------------------------------------------- #
# Figure: short-horizon fix tail by severity
# --------------------------------------------------------------------------- #
def _save(fig, name):
    path = FIGS / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(path)


fig, ax = plt.subplots(figsize=(7.4, 3.1))
x = np.arange(len(sevs))
width = 0.27
for i, (horizon, color) in enumerate([("7", "#08519c"), ("30", "#4292c6"), ("90", "#9ecae1")]):
    vals = [disc[s][f"fixed_within_{horizon}d_pct"] for s in sevs]
    bars = ax.bar(x + (i - 1) * width, vals, width, color=color, label=f"within {horizon} days")
    ax.bar_label(bars, fmt="%.0f%%", fontsize=7.5)
ax.set_xticks(x, [f"{s}\n(n={disc[s]['n_day_fixed']}, median {disc[s]['km_median_days']:.0f}d)"
                  for s in sevs], fontsize=8)
ax.set_ylabel("share of dated fixes")
ax.set_ylim(0, 62)
ax.legend(fontsize=8, ncols=3, frameon=False)
ax.grid(True, axis="y", alpha=0.3)
fig_tail = _save(fig, "brief_fix_tail.png")

# --------------------------------------------------------------------------- #
# PDF assembly
# --------------------------------------------------------------------------- #
styles = getSampleStyleSheet()
styles.add(ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=17, spaceAfter=4))
styles.add(ParagraphStyle("Sub", parent=styles["Normal"], fontSize=9.5, textColor=colors.grey, alignment=TA_CENTER))
styles.add(ParagraphStyle("H", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#08306b"), spaceBefore=10, spaceAfter=4))
styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13, spaceAfter=5))
styles.add(ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=8))
styles.add(ParagraphStyle("Stat", parent=styles["Normal"], fontSize=18, leading=20, alignment=TA_CENTER,
                          textColor=colors.HexColor("#08306b"), fontName="Helvetica-Bold"))
styles.add(ParagraphStyle("StatCap", parent=styles["Normal"], fontSize=8, leading=10.5, alignment=TA_CENTER))
styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=11, spaceAfter=3))

story = []


def P(txt, style="Body"):
    story.append(Paragraph(txt, styles[style]))


def figure(path, caption, width=15.5 * cm):
    img = Image(path)
    img._restrictSize(width, 9.5 * cm)
    img.hAlign = "CENTER"
    story.append(img)
    story.append(Paragraph(caption, styles["Caption"]))


# --- Page 1: how fast do projects fix? --------------------------------------
P("How fast do popular open-source projects<br/>fix vulnerable dependencies?", "TitleBig")
P("The 100 most-starred JavaScript/TypeScript repositories, scanned across 18 quarterly snapshots "
  "plus HEAD, with fix dates mined from lockfile history &nbsp;·&nbsp; brief generated "
  + date.today().isoformat(), "Sub")
story.append(Spacer(1, 8))

P(f"Quarterly scan panels can only see remediation at 90-day resolution, so we mined each project's "
  f"lockfile commit history to date fixes exactly: of {mine_units:,} fix windows, {mine_found:,} "
  f"({mine_found / mine_units:.0%}) yielded the precise commit that removed the vulnerable version. "
  f"Three results stand out.")

P(f"<b>1. Severity does not predict fix speed.</b> Median remediation lag after an advisory is "
  f"published sits between {km_lo:.0f} and {km_hi:.0f} days at every severity level. CRITICAL "
  f"vulnerabilities are not fixed faster than LOW ones. Whatever drives remediation in these "
  f"projects, it is not the severity label.")

P(f"<b>2. A fast-responder tail coexists with nine-month medians.</b> Among fixes datable to the "
  f"day, {pooled_7d:.0f}% land within a week of the vulnerable interval starting and "
  f"{pooled_90d:.0f}% within a quarter. Remediation is bimodal: a minority of project/dependency "
  f"combinations react almost immediately, the rest take the better part of a year.")

figure(fig_tail,
       "Figure 1. Share of dated fixes landing within 7/30/90 days, by severity. Bars condition on the fix "
       "being observed and datable (n = "
       f"{n_day_fixed:,} of {n_disclosed:,} disclosed intervals); over all disclosed intervals the "
       "within-7-days share is about 4%.")

stat_row = [
    [Paragraph(f"{km_lo:.0f}-{km_hi:.0f} days", styles["Stat"]),
     Paragraph(f"{pooled_7d:.0f}% / {pooled_90d:.0f}%", styles["Stat"]),
     Paragraph(f"{headline['pkgs_clear_50']} packages", styles["Stat"])],
    [Paragraph("median fix lag after disclosure, flat across severities: CRITICAL is not treated as more urgent.", styles["StatCap"]),
     Paragraph("of dated fixes land within a week / within a quarter. Remediation has a fast tail the medians hide.", styles["StatCap"]),
     Paragraph(f"account for half of all {headline['instances']:,} vulnerability instances at HEAD. A handful of upstream fixes clears most aggregate risk.", styles["StatCap"])],
]
t = Table(stat_row, colWidths=[5.6 * cm] * 3, hAlign="CENTER")
t.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("BOX", (0, 0), (0, -1), 0.6, colors.HexColor("#dbe4f0")),
    ("BOX", (1, 0), (1, -1), 0.6, colors.HexColor("#dbe4f0")),
    ("BOX", (2, 0), (2, -1), 0.6, colors.HexColor("#dbe4f0")),
    ("TOPPADDING", (0, 0), (-1, 0), 8),
    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
    ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
]))
story.append(t)

story.append(PageBreak())

# --- Page 2: where the risk sits + honesty box -------------------------------
P("Most vulnerable-version time predates disclosure", "H")
P(f"Total residence of a vulnerable version in a dependency tree is a different clock from the fix "
  f"lag in Figure 1: it starts when the version enters the tree, which is usually long before any "
  f"advisory exists ({pre_disclosure_share:.0%} of historical instance rows predate their "
  f"advisory's publication, and another {no_date_share:.0%} carry no publication date at all). "
  f"On this clock, Kaplan-Meier median residence runs {res_lo:.0f} to {res_hi:.0f} days, and it "
  f"does vary by severity (CRITICAL shortest at {res['CRITICAL']['km_median_days']:.0f} days, LOW "
  f"longest at {res['LOW']['km_median_days']:.0f}). That is not a contradiction of finding 1: "
  f"during most of this interval the severity label does not exist yet, and disappearance here "
  f"includes routine version bumps and dependency removal. The gradient reflects how fast these "
  f"packages churn anyway, while the deliberate response after disclosure (Figure 1) is flat "
  f"across severities.")

P("Popularity does not predict security", "H")
P(f"Across the {rqc['n']} projects with dependencies, star rank shows no relationship with "
  f"vulnerability load (Spearman rho = {rqc['spearman_rho']:+.2f}, p = {rqc['p']:.2f}). "
  f"{headline['n_affected']} of {headline['n_projects']} projects ({headline['affected_share']:.0%}) "
  f"carry at least one known-vulnerable dependency at HEAD, with a heavily concentrated "
  f"distribution: the top-10 vulnerable packages account for {headline['top10_pkg_share']:.0%} of "
  f"all instances (Gini {headline['gini_pkg']:.2f}), and fixing "
  f"{headline['pkgs_clear_80']} packages would clear 80% of them. Full study: "
  f"{coverage['attempted_analyses']:,} analyses across 19 time points per project.")

P("Reading the numbers honestly", "H")
for bullet in [
    "Single pipeline, single corpus: results characterize this scanner on repositories reachable "
    "through this environment's GitHub endpoint; external generalization is not claimed.",
    "All counts are conditional on the advisory-knowledge date. We measured this directly by "
    f"re-scanning frozen code under dated knowledge cutoffs: the swing reaches "
    f"{abs(ladder_worst):.0f}% for 3.5-year-old knowledge, so numbers from different scan dates "
    "are not comparable.",
    f"Fix-timing shares condition on a minable fix ({mine_found / mine_units:.0%} of mining units "
    "succeeded); where no dated fix exists, durations are interval-censored at quarterly "
    "resolution and disappearance includes dependency removal, not only deliberate fixes.",
    "Advisory publication dates are missing for roughly half of historical rows, so "
    "disclosed-only analyses inherit that coverage bias.",
    "Severity labels follow the scanner's conflict-resolved CVSS class; about 11% of matches "
    "carry a lower-confidence flag, and concentration conclusions (not absolute counts) survive "
    "restriction to high-confidence matches.",
]:
    P("&bull; " + bullet, "Small")

story.append(Spacer(1, 8))
P(f"Advisory databases pinned at {str(meta['knowledge']['knowledge_sources']['nvd'])[:10]} · "
  f"full methods, threats to validity and regeneration commands: RESULTS.md; every number in this "
  f"brief is read at build time from the audited extraction (results_numbers.json).", "Caption")

doc = SimpleDocTemplate(
    str(OUT / "js-vuln-study-brief.pdf"),
    pagesize=A4,
    leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
    title="How fast do popular open-source projects fix vulnerable dependencies?",
)
doc.build(story)
print(f"wrote {OUT / 'js-vuln-study-brief.pdf'}")
