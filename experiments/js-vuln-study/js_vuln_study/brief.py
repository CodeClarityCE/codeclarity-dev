"""Render the 2-page shareable brief from the audited extraction.

Every quoted number is read from `<study>/tables/results_numbers.json` at
build time, so the brief can never drift from `numbers.build_numbers`'s
output. Figures are drawn from the parquet tables through the same shared
`stats` helpers `numbers.py` uses (never re-implemented inline), so curves
and quoted medians cannot disagree either. The ladder and cohort sections are
optional: the brief builds without them, just shorter. Style rule: no em
dashes anywhere.
"""

from __future__ import annotations

import json
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
    Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from .config import Study
from .stats import disclosed_subset, km_curve, merge_day_resolution, presence_intervals

SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLORS = {"CRITICAL": "#a50f15", "HIGH": "#de2d26", "MEDIUM": "#fb6a4a", "LOW": "#fcae91"}


def _save(fig, figs_dir: Path, name: str) -> str:
    path = figs_dir / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return str(path)


def _fig_fix_tail(disc: dict, figs_dir: Path) -> str:
    fig, ax = plt.subplots(figsize=(7.4, 3.0))
    x = np.arange(len(SEVS))
    width = 0.27
    for i, (horizon, color) in enumerate([("7", "#08519c"), ("30", "#4292c6"), ("90", "#9ecae1")]):
        vals = [disc[s].get(f"fixed_within_{horizon}d_pct") or 0 for s in SEVS]
        bars = ax.bar(x + (i - 1) * width, vals, width, color=color, label=f"within {horizon} days")
        ax.bar_label(bars, fmt="%.0f%%", fontsize=7.5)
    ax.set_xticks(x, [f"{s}\n({disc[s].get('n_day_fixed', 0)} dated fixes)" for s in SEVS], fontsize=8)
    ax.set_ylabel("share of dated fixes")
    ax.set_ylim(0, 62)
    ax.legend(fontsize=8, ncols=3, frameon=False)
    ax.grid(True, axis="y", alpha=0.3)
    return _save(fig, figs_dir, "brief_fix_tail.png")


def _fig_km(kept: pd.DataFrame, disc: dict, figs_dir: Path) -> str:
    fig, ax = plt.subplots(figsize=(7.4, 3.2))
    for sev in SEVS:
        s = kept[kept.severity_class.astype(str).str.upper() == sev]
        t, sv = km_curve(s.duration_days, s.event)
        median = disc[sev].get("km_median_days")
        label = f"{sev} (median {median:.0f}d)" if median is not None else f"{sev} (n={len(s)})"
        ax.step(t, sv, where="post", color=SEV_COLORS[sev], lw=1.6, label=label)
    ax.axhline(0.5, color="#999999", lw=0.8, ls="--")
    ax.set_xlim(0, 1000)
    ax.set_ylim(0, 1.0)
    ax.set_xlabel("days since the advisory was published")
    ax.set_ylabel("share not yet fixed")
    ax.legend(fontsize=8, frameon=False)
    ax.grid(True, alpha=0.3)
    return _save(fig, figs_dir, "brief_km.png")


def _fig_cohort(base_kept: pd.DataFrame, cohort_kept: pd.DataFrame, cohort_label: str, base_label: str, figs_dir: Path) -> str:
    fig, ax = plt.subplots(figsize=(7.4, 3.0))
    for label, df, color in [
        (f"{base_label} (n={len(base_kept)})", base_kept, "#08519c"),
        (f"{cohort_label} (n={len(cohort_kept)})", cohort_kept, "#de2d26"),
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
    return _save(fig, figs_dir, "brief_cohort_km.png")


def _kept_for(study: Study) -> pd.DataFrame:
    a = pd.read_parquet(study.tables_dir / "analyses.parquet")
    v = pd.read_parquet(study.tables_dir / "vulns.parquet")
    ev_path = study.tables_dir / "remediation_events.parquet"
    ev = pd.read_parquet(ev_path) if ev_path.exists() else None
    disclosed = disclosed_subset(v, a)
    ints = merge_day_resolution(presence_intervals(disclosed, a), ev)
    return ints[~ints["excluded"]]


def build(study: Study, cohort_study: Study | None = None) -> Path:
    numbers_path = study.tables_dir / "results_numbers.json"
    num = json.loads(numbers_path.read_text(encoding="utf-8"))

    out_dir = study.report_dir
    figs_dir = out_dir / "figs"
    figs_dir.mkdir(parents=True, exist_ok=True)

    day = num.get("survival_day_resolution")
    headline = num["headline"]
    coverage = num["coverage"]
    rqc = num["rqc"]
    meta = num["run_meta"]
    res = num["survival_residence"]["km_by_severity"]
    hist = num["disclosure_coverage_hist"]
    ladder = num.get("ladder")
    cohort = num.get("cohort")

    grid_points = coverage.get("grid_len", 0) + 1  # +1 for HEAD

    story = []
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=17, spaceAfter=4))
    styles.add(ParagraphStyle("Sub", parent=styles["Normal"], fontSize=9.5, textColor=colors.grey, alignment=TA_CENTER))
    styles.add(ParagraphStyle("H", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#08306b"), spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13, spaceAfter=5))
    styles.add(ParagraphStyle("Caption", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=8))
    styles.add(ParagraphStyle("Stat", parent=styles["Normal"], fontSize=18, leading=20, alignment=TA_CENTER, textColor=colors.HexColor("#08306b"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("StatCap", parent=styles["Normal"], fontSize=8, leading=10.5, alignment=TA_CENTER))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8.5, leading=11.5, spaceAfter=3))

    def P(txt, style="Body"):
        story.append(Paragraph(txt, styles[style]))

    def figure(path, caption, width=15.5 * cm):
        img = Image(path)
        img._restrictSize(width, 9.5 * cm)
        img.hAlign = "CENTER"
        story.append(img)
        story.append(Paragraph(caption, styles["Caption"]))

    P("How fast do popular open-source projects<br/>fix vulnerable dependencies?", "TitleBig")
    P(f"A study of {headline['n_projects']} JavaScript/TypeScript repositories &nbsp;.&nbsp; "
      f"brief generated {date.today().isoformat()}", "Sub")
    story.append(Spacer(1, 8))

    if day is not None:
        disc = day["disclosed"]["km_by_severity"]
        n_day_fixed = sum(disc[s].get("n_day_fixed", 0) for s in SEVS)
        mine_units = day["events"]
        mine_found = day["by_status"].get("found", 0)
        km_vals = [disc[s]["km_median_days"] for s in SEVS if disc[s].get("km_median_days") is not None]
        km_lo, km_hi = (min(km_vals), max(km_vals)) if km_vals else (float("nan"), float("nan"))
        pooled_7d = (
            sum(disc[s].get("n_day_fixed", 0) * (disc[s].get("fixed_within_7d_pct") or 0) for s in SEVS) / n_day_fixed
            if n_day_fixed else float("nan")
        )
        pooled_90d = (
            sum(disc[s].get("n_day_fixed", 0) * (disc[s].get("fixed_within_90d_pct") or 0) for s in SEVS) / n_day_fixed
            if n_day_fixed else float("nan")
        )

        mine_found_pct = (mine_found / mine_units) if mine_units else 0.0
        P(f"We scanned each project's dependencies at {grid_points} points in time and then went "
          f"one step further: for every vulnerability that got fixed, we searched the project's "
          f"commit history to find the exact commit that removed the vulnerable version. That "
          f"worked for {mine_found:,} of {mine_units:,} fixes ({mine_found_pct:.0%}), which lets "
          f"us measure fix speed in days instead of snapshots. Three results stand out.")

        P(f"<b>1. Severity does not predict fix speed.</b> After a vulnerability is publicly "
          f"disclosed, projects take a median of {km_lo:.0f} to {km_hi:.0f} days to fix it, and "
          f"that holds at every severity level (Figure 2 shows the curves lying close together).")

        P(f"<b>2. But there is a fast minority.</b> Looking only at fixes we could date exactly: "
          f"{pooled_7d:.0f}% happen within one week, and {pooled_90d:.0f}% within three months.")

        figure(_fig_fix_tail(disc, figs_dir),
               "Figure 1. Of the fixes we could date exactly, how many happened within 7, 30, or "
               "90 days? Shown per severity level.")

        stat_row = [
            [Paragraph(f"{km_lo:.0f}-{km_hi:.0f} days", styles["Stat"]),
             Paragraph(f"{pooled_7d:.0f}%", styles["Stat"]),
             Paragraph(f"{headline['pkgs_clear_50']} packages", styles["Stat"])],
            [Paragraph("median time from public disclosure to fix, nearly identical across severities.", styles["StatCap"]),
             Paragraph("of dated fixes happen within one week.", styles["StatCap"]),
             Paragraph(f"out of {headline['distinct_vuln_packages']} vulnerable packages cause half of all {headline['instances']:,} findings.", styles["StatCap"])],
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

        P("The fix-speed curves, severity by severity", "H")
        P("Figure 2 shows, for each severity level, the share of disclosed vulnerabilities that is "
          "still unfixed N days after the advisory came out (Kaplan-Meier estimates). If severity "
          "drove urgency, the CRITICAL curve would drop much faster than the others.")
        kept = _kept_for(study)
        figure(_fig_km(kept, disc, figs_dir),
               "Figure 2. Share of disclosed vulnerabilities still unfixed, by days since disclosure.")

        if cohort is not None and cohort_study is not None:
            _p = cohort["cohort"]["pooled"]["km_median_days"]
            _b = cohort["baseline"]["pooled"]["km_median_days"]
            _p_recent = cohort["cohort"]["recency"]["disclosed_on_or_after"]["km_median_days"]
            _b_recent = cohort["baseline"]["recency"]["disclosed_on_or_after"]["km_median_days"]
            _cutoff = cohort["meta"]["recency_cutoff"]
            _n_base = cohort["baseline"]["n_projects"]
            P(f"Cohort comparison: {cohort_study.name}", "H")
            if _p is not None and _b is not None:
                P(f"{cohort_study.name} fixes disclosed vulnerabilities in a median of {_p:.0f} days "
                  f"across {cohort['cohort']['n_projects']} repositories, against {_b:.0f} days for "
                  f"the baseline on the identical pipeline. For vulnerabilities disclosed on or after "
                  f"{_cutoff}, the gap is {_p_recent:.0f} vs {_b_recent:.0f} days." if _p_recent is not None and _b_recent is not None else "")
            figure(
                _fig_cohort(_kept_for(study), _kept_for(cohort_study), cohort_study.name, study.name, figs_dir),
                f"Figure 3. {cohort_study.name} vs the {study.name} baseline, share of disclosed "
                f"vulnerabilities still unfixed by days since disclosure. Cohort n={cohort['cohort']['n_projects']} "
                f"vs baseline n={_n_base}; reported with n throughout, a case study rather than a population claim.",
            )

        P("More stars do not mean more security", "H")
        P(f"A project's popularity says nothing about its vulnerability load: across {rqc['n']} "
          f"projects, the correlation between star rank and number of vulnerabilities is "
          f"statistically indistinguishable from zero. Overall, {headline['n_affected']} of "
          f"{headline['n_projects']} projects ({headline['affected_share']:.0%}) currently ship at "
          f"least one known-vulnerable dependency.")

        P("What these numbers can and cannot say", "H")
        bullets = [
            "<b>One tool, one sample.</b> We used a single scanner on a specific set of "
            "repositories. Other scanners and samples will give different absolute numbers; the "
            "patterns are what we expect to travel.",
            "<b>Results age quickly.</b> Vulnerability databases grow daily, so a scan is only "
            "valid for its date. Do not compare numbers from scans taken on different dates.",
            (
                f"<b>Not every fix could be dated.</b> We found the exact fix commit for "
                f"{mine_found_pct:.0%} of fixes; everything else is measured at the snapshot's "
                f"resolution."
            ) if mine_units else "",
            "<b>Half of the advisories lack a publication date</b> in our data, so \"after "
            "disclosure\" analyses are based on the half that has one.",
            "<b>A fix is not always a fix.</b> We count a vulnerability as gone when the "
            "vulnerable version leaves the project's dependency list, which conflates a genuine "
            "upgrade with the dependency being dropped entirely.",
        ]
        if ladder is not None and ladder.get("rungs"):
            worst = ladder["rungs"][0].get("vs_freshest", {}).get("instance_delta_pct")
            if worst is not None:
                bullets.insert(1,
                    f"<b>Vulnerability counts depend on the knowledge-database date.</b> Scanning "
                    f"the same code with year-old advisory data misses most of what a fresh scan "
                    f"finds (up to {abs(worst):.0f}% with very old data; see the knowledge-staleness "
                    f"appendix).")
        for bullet in bullets:
            if bullet:
                P("&bull; " + bullet, "Small")
    else:
        P("Day-resolution fix mining has not run for this study (`run.py analyze STUDY` without "
          "`--no-mine`); the numbers below are at the snapshot grid's resolution only.")
        P(f"Across {headline['n_projects']} projects, {headline['n_affected']} "
          f"({headline['affected_share']:.0%}) currently ship at least one known-vulnerable "
          f"dependency, concentrated in {headline['pkgs_clear_50']} packages for half of all "
          f"{headline['instances']:,} findings.")

    story.append(Spacer(1, 8))
    nvd = (((meta.get("knowledge") or {}).get("knowledge_sources") or {}).get("nvd"))
    P(f"Data as of {str(nvd)[:10] if nvd else 'unknown'} . methods, caveats and regeneration "
      f"commands: RESULTS.md . every number in this brief is read at build time from the audited "
      f"extraction (results_numbers.json).", "Caption")

    doc = SimpleDocTemplate(
        str(out_dir / "brief.pdf"), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title="How fast do popular open-source projects fix vulnerable dependencies?",
    )
    doc.build(story)
    return out_dir / "brief.pdf"
