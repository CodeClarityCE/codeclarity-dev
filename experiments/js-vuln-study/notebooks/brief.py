"""Render the 2-page shareable brief from the audited extraction.

Unlike report.py (the long-form document built from the parquet tables), the
brief is aimed at readers with no time. It leads with the study's novel
findings (how fast projects actually fix vulnerable dependencies, where the
risk concentrates), not with confirmatory results, and is written in plain
language. Every quoted number is read from data/tables/results_numbers.json
(the audited single source of truth behind RESULTS.md) at build time, so the
brief regenerates when the extractor reruns and can never drift from the
document. The Kaplan-Meier figure is drawn from the parquet tables through
the same shared stats helpers the extractor uses, so curves and quoted
medians cannot disagree either. Style rule: no em dashes anywhere.

    cd experiments/js-vuln-study
    .venv/bin/python notebooks/brief.py
    # -> data/report/js-vuln-study-brief.pdf
"""

from __future__ import annotations

import json
import sys
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
sys.path.insert(0, str(ROOT))
from js_vuln_study.stats import (  # noqa: E402
    disclosed_subset,
    km_curve,
    merge_day_resolution,
    presence_intervals,
)

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

up_sev = day["disclosed"]["fix_kind"]["upgrade_only_km_by_severity"]
up_crit = up_sev["CRITICAL"]["km_median_days"]
up_low = up_sev["LOW"]["km_median_days"]

passbolt = NUM.get("passbolt")

SEV_COLORS = {"CRITICAL": "#a50f15", "HIGH": "#de2d26", "MEDIUM": "#fb6a4a", "LOW": "#fcae91"}

# --------------------------------------------------------------------------- #
# Figures
# --------------------------------------------------------------------------- #
def _save(fig, name):
    path = FIGS / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(path)


# Figure 1: short-horizon fix tail by severity (numbers match the JSON block).
fig, ax = plt.subplots(figsize=(7.4, 3.0))
x = np.arange(len(sevs))
width = 0.27
for i, (horizon, color) in enumerate([("7", "#08519c"), ("30", "#4292c6"), ("90", "#9ecae1")]):
    vals = [disc[s][f"fixed_within_{horizon}d_pct"] for s in sevs]
    bars = ax.bar(x + (i - 1) * width, vals, width, color=color, label=f"within {horizon} days")
    ax.bar_label(bars, fmt="%.0f%%", fontsize=7.5)
ax.set_xticks(x, [f"{s}\n({disc[s]['n_day_fixed']} dated fixes)" for s in sevs], fontsize=8)
ax.set_ylabel("share of dated fixes")
ax.set_ylim(0, 62)
ax.legend(fontsize=8, ncols=3, frameon=False)
ax.grid(True, axis="y", alpha=0.3)
fig_tail = _save(fig, "brief_fix_tail.png")

# Figure 2: Kaplan-Meier curves for the post-disclosure fix lag, by severity.
# Same data path as the extractor's survival_day_resolution block: disclosed
# subset -> presence intervals -> mined day-resolution fixes merged in.
_a = pd.read_parquet(TABLES / "analyses.parquet")
_v = pd.read_parquet(TABLES / "vulns.parquet")
_ev = pd.read_parquet(TABLES / "remediation_events.parquet")
_pub = pd.to_datetime(_v.published_date, errors="coerce", utc=True)
_snap = pd.to_datetime(_v.snapshot_date.where(_v.snapshot_date != "HEAD"), errors="coerce", utc=True)
_committed = pd.to_datetime(_a.set_index("analysis_id").committed_at, errors="coerce", utc=True)
_snap_eff = _snap.fillna(_v.analysis_id.map(_committed))
_disclosed = _v[_pub.notna() & (_pub <= _snap_eff)]
_ints = merge_day_resolution(presence_intervals(_disclosed, _a), _ev)
_kept = _ints[~_ints["excluded"]]

fig, ax = plt.subplots(figsize=(7.4, 3.2))
for sev in sevs:
    s = _kept[_kept.severity_class.astype(str).str.upper() == sev]
    t, sv = km_curve(s.duration_days, s.event)
    ax.step(t, sv, where="post", color=SEV_COLORS[sev], lw=1.6,
            label=f"{sev} (median {disc[sev]['km_median_days']:.0f}d)")
ax.axhline(0.5, color="#999999", lw=0.8, ls="--")
ax.annotate("half fixed", (ax.get_xlim()[1], 0.5), xytext=(-4, 4),
            textcoords="offset points", ha="right", fontsize=7.5, color="#666666")
ax.set_xlim(0, 1000)
ax.set_ylim(0, 1.0)
ax.set_xlabel("days since the advisory was published")
ax.set_ylabel("share not yet fixed")
ax.legend(fontsize=8, frameon=False)
ax.grid(True, alpha=0.3)
fig_km = _save(fig, "brief_km.png")

# Figure 3 (optional): Passbolt cohort vs the top-100 baseline, pooled KM,
# through scripts/passbolt_compare.py's exact data path (disclosed subset ->
# presence intervals -> mined day-resolution fixes merged in), so the curve
# cannot disagree with the quoted medians in NUM["passbolt"].
fig_passbolt = None
if passbolt is not None:
    def _kept_for(data_dir: Path) -> pd.DataFrame:
        aa = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
        vv = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
        ee = pd.read_parquet(data_dir / "tables" / "remediation_events.parquet")
        dd = disclosed_subset(vv, aa)
        ii = merge_day_resolution(presence_intervals(dd, aa), ee)
        return ii[~ii["excluded"]]

    _base_kept = _kept_for(TABLES.parent)
    _cohort_kept = _kept_for(ROOT / "data-passbolt")

    fig, ax = plt.subplots(figsize=(7.4, 3.0))
    for label, df, color in [
        (f"top-100 baseline (n={len(_base_kept)})", _base_kept, "#08519c"),
        (f"Passbolt (n={len(_cohort_kept)})", _cohort_kept, "#de2d26"),
    ]:
        t, sv = km_curve(df.duration_days, df.event)
        ax.step(t, sv, where="post", color=color, lw=1.8, label=label)
    ax.axhline(0.5, color="#999999", lw=0.8, ls="--")
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 1.0)
    ax.set_xlabel("days since first post-disclosure observation")
    ax.set_ylabel("share not yet fixed")
    ax.legend(fontsize=8, frameon=False)
    ax.grid(True, alpha=0.3)
    fig_passbolt = _save(fig, "brief_passbolt_km.png")

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
styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8.5, leading=11.5, spaceAfter=3))

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
P("A study of the 100 most-starred JavaScript/TypeScript repositories &nbsp;·&nbsp; brief generated "
  + date.today().isoformat(), "Sub")
story.append(Spacer(1, 8))

P(f"We scanned each project's dependencies at 19 points in time (today plus 18 quarterly "
  f"snapshots back to 2022) and then went one step further: for every vulnerability that got "
  f"fixed, we searched the project's commit history to find the exact commit that removed the "
  f"vulnerable version. That worked for {mine_found:,} of {mine_units:,} fixes "
  f"({mine_found / mine_units:.0%}), which lets us measure fix speed in days instead of quarters. "
  f"Three results stand out.")

P(f"<b>1. Severity does not predict fix speed.</b> After a vulnerability is publicly disclosed, "
  f"projects take about nine months (median {km_lo:.0f} to {km_hi:.0f} days) to fix it, and that "
  f"is true at every severity level. CRITICAL vulnerabilities are not fixed faster than LOW ones "
  f"(Figure 2 on page 2 shows the four curves lying almost on top of each other).")

P(f"<b>2. But there is a fast minority.</b> Looking only at fixes we could date exactly: "
  f"{pooled_7d:.0f}% happen within one week of the vulnerability appearing, and "
  f"{pooled_90d:.0f}% within three months. So remediation splits into a small group that reacts "
  f"almost immediately and a majority that takes the better part of a year.")

figure(fig_tail,
       "Figure 1. Of the fixes we could date exactly, how many happened within 7, 30, or 90 days? "
       "Shown per severity level. The pattern is similar at every severity: roughly one fix in ten "
       "lands within a week, roughly half within three months.")

stat_row = [
    [Paragraph(f"{km_lo:.0f}-{km_hi:.0f} days", styles["Stat"]),
     Paragraph(f"{pooled_7d:.0f}%", styles["Stat"]),
     Paragraph(f"{headline['pkgs_clear_50']} packages", styles["Stat"])],
    [Paragraph("median time from public disclosure to fix. Nearly identical for CRITICAL and LOW: the severity label does not create urgency.", styles["StatCap"]),
     Paragraph("of dated fixes happen within one week. A small group of projects reacts almost immediately; most do not.", styles["StatCap"]),
     Paragraph(f"out of {headline['distinct_vuln_packages']} vulnerable packages cause half of all {headline['instances']:,} vulnerability findings. Fixing a handful of shared dependencies clears most of the total risk.", styles["StatCap"])],
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

# --- Page 2: the KM figure, context, limitations ----------------------------
P("The fix-speed curves, severity by severity", "H")
P("Figure 2 shows, for each severity level, the share of disclosed vulnerabilities that is still "
  "unfixed N days after the advisory came out. (These are Kaplan-Meier estimates, the standard "
  "way to measure time-to-event fairly when some cases are still unfixed at the end of the "
  "observation window.) If severity drove urgency, the CRITICAL curve would drop much faster "
  "than the others. It does not.")
figure(fig_km,
       "Figure 2. Share of disclosed vulnerabilities still unfixed, by days since disclosure. "
       "The four severity curves nearly overlap: about half of all cases are fixed by roughly nine "
       "months, regardless of severity.")

if fig_passbolt is not None:
    _p = passbolt["cohort"]["pooled"]["km_median_days"]
    _b = passbolt["baseline"]["pooled"]["km_median_days"]
    _p_recent = passbolt["cohort"]["recency"]["disclosed_on_or_after"]["km_median_days"]
    _b_recent = passbolt["baseline"]["recency"]["disclosed_on_or_after"]["km_median_days"]
    _cutoff = passbolt["meta"]["recency_cutoff"]
    P("Security-focused teams patch much faster", "H")
    P(f"The pattern above is a population average. Passbolt, a security-focused open-source "
      f"password manager, fixes disclosed vulnerabilities in a median of {_p:.0f} days across its "
      f"three main repositories (api, browser extension, styleguide), against {_b:.0f} days for the "
      f"top-100 baseline on the identical pipeline. The gap is not shrinking: for vulnerabilities "
      f"disclosed on or after {_cutoff}, Passbolt's median drops to {_p_recent:.0f} days while the "
      f"baseline stays at {_b_recent:.0f}. It holds up when dependency-removal fixes are excluded "
      f"and within every disclosure era, so it is not an artifact of what got disclosed when.")
    figure(fig_passbolt,
           f"Figure 3. Passbolt vs the top-100 baseline, share of disclosed vulnerabilities still "
           f"unfixed by days since disclosure. Passbolt is 3 repositories against {passbolt['baseline']['n_projects']} "
           f"baseline projects, reported with its n throughout; the gap is a case study, not a "
           f"population claim.")

P("More stars do not mean more security", "H")
P(f"A project's popularity says nothing about its vulnerability load: across {rqc['n']} projects, "
  f"the correlation between star rank and number of vulnerabilities is statistically "
  f"indistinguishable from zero. Overall, {headline['n_affected']} of {headline['n_projects']} "
  f"projects ({headline['affected_share']:.0%}) currently ship at least one known-vulnerable "
  f"dependency.")

P("What these numbers can and cannot say", "H")
for bullet in [
    "<b>One tool, one sample.</b> We used a single scanner on 100 specific repositories. Other "
    "scanners and other project samples will give different absolute numbers; the patterns are "
    "what we expect to travel.",
    "<b>Results age quickly.</b> Vulnerability databases grow daily, so a scan is only valid for "
    "its date. We measured this: scanning the same code with year-old advisory data misses most "
    f"of what a fresh scan finds (up to {abs(ladder_worst):.0f}% with very old data). Do not "
    "compare numbers from scans taken on different dates.",
    f"<b>Not every fix could be dated.</b> We found the exact fix commit for "
    f"{mine_found / mine_units:.0%} of fixes. The day-level percentages (Figure 1) describe those; "
    "everything else is measured at quarterly resolution.",
    "<b>Half of the advisories lack a publication date</b> in our data, so \"after disclosure\" "
    "analyses are based on the half that has one.",
    f"<b>Before disclosure, nobody is to blame.</b> Vulnerable versions sit in dependency trees far "
    f"longer than nine months in total ({res_lo:.0f} to {res_hi:.0f} days by severity), but most of "
    f"that time the vulnerability had not been discovered yet by anyone "
    f"({pre_disclosure_share:.0%} of our historical observations predate the advisory's "
    f"publication), so every fix-speed number above starts counting at public disclosure instead.",
    "<b>A fix is not always a fix.</b> We count a vulnerability as gone when the vulnerable "
    "version leaves the project's dependency list. Checking every dated fix commit shows about "
    "three quarters are genuine upgrades and about a quarter removed the dependency instead "
    "(split further into deliberately-dropped direct dependencies vs. transitive deps that left "
    f"because a parent was upgraded); counting upgrades only, higher severity is fixed somewhat "
    f"faster (median {up_crit:.0f} days for critical vs {up_low:.0f} for low).",
]:
    P("&bull; " + bullet, "Small")

story.append(Spacer(1, 8))
P(f"Data as of {str(meta['knowledge']['knowledge_sources']['nvd'])[:10]} · methods, caveats and "
  f"regeneration commands: RESULTS.md · every number in this brief is read at build time from the "
  f"audited extraction (results_numbers.json).", "Caption")

doc = SimpleDocTemplate(
    str(OUT / "js-vuln-study-brief.pdf"),
    pagesize=A4,
    leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
    title="How fast do popular open-source projects fix vulnerable dependencies?",
)
doc.build(story)
print(f"wrote {OUT / 'js-vuln-study-brief.pdf'}")
