"""End-to-end smoke tests for the brief PDF: it must build both with and
without day-resolution mining data and a cohort comparison present."""

from __future__ import annotations

import re

import pytest

from js_vuln_study import brief, numbers
from js_vuln_study.config import Study

from conftest import row, write_manifest, write_tables
from test_numbers import _analysis_row, _study, _vuln_row


def _page_count(pdf_path) -> int:
    """Read a PDF's own `/Type /Pages` object's `/Count` rather than pulling
    in a PDF-parsing dependency for one number. `/Count` and `/Type` can
    appear in either order within the dict, so match the whole `<< ... >>`
    block (no nested dicts in a `/Pages` object) and search within it."""
    data = pdf_path.read_bytes()
    obj = re.search(rb"<<([^<>]*?/Type\s*/Pages[^<>]*?)>>", data, re.DOTALL)
    assert obj, f"could not find the /Pages object in {pdf_path}"
    m = re.search(rb"/Count\s*(\d+)", obj.group(1))
    assert m, f"/Pages object has no /Count in {pdf_path}"
    return int(m.group(1))


def _populated(tmp_path, name) -> Study:
    s = _study(tmp_path, name)
    write_manifest(s.manifest_path, [
        row(npm_name="p/one", git_url="https://github.com/p/one", snapshot_date="HEAD", state="done"),
        row(npm_name="p/one", git_url="https://github.com/p/one", snapshot_date="2024-01-01", state="done"),
    ])
    write_tables(
        s.tables_dir,
        analyses_rows=[_analysis_row("p1", "p/one", "HEAD"), _analysis_row("p1", "p/one", "2024-01-01")],
        vulns_rows=[
            _vuln_row("p1", "p/one", "HEAD", "CVE-1", "lodash"),
            _vuln_row("p1", "p/one", "2024-01-01", "CVE-1", "lodash", severity_class="CRITICAL"),
        ],
        run_meta={"run_id": "r1", "knowledge": {"knowledge_sources": {"nvd": "2026-08-01"}, "epss_rows": 10},
                  "analyzer_steps": [], "api_version": "1.0"},
    )
    return s


def _mined(tmp_path, name) -> Study:
    """`_populated` plus a day-resolution fix event, so the brief takes the
    full (non-fallback) path where the cohort section lives."""
    s = _populated(tmp_path, name)
    write_tables(
        s.tables_dir,
        analyses_rows=[_analysis_row("p1", "p/one", "HEAD"), _analysis_row("p1", "p/one", "2024-01-01")],
        vulns_rows=[
            _vuln_row("p1", "p/one", "HEAD", "CVE-1", "lodash"),
            _vuln_row("p1", "p/one", "2024-01-01", "CVE-1", "lodash", severity_class="CRITICAL"),
        ],
        run_meta={"knowledge": {"knowledge_sources": {"nvd": "2026-08-01"}, "epss_rows": 10}},
        events_rows=[
            {"npm_name": "p/one", "project_id": "p1", "affected_dependency": "lodash",
             "affected_version": "1.0.0", "last_seen": "2024-01-01", "next_snapshot": "2026-08-01",
             "lockfile": "yarn.lock", "fix_commit_sha": "f" * 40, "fixed_at": "2024-01-10T00:00:00Z",
             "fix_kind": "upgraded", "fix_to_version": "1.0.1", "method": "linear_scan", "status": "found"},
        ],
    )
    return s


def test_brief_builds_without_mining_or_cohort_data(tmp_path):
    s = _populated(tmp_path, "solo")
    numbers.build_numbers(s)
    pdf = brief.build(s)
    assert pdf.exists()
    assert pdf.stat().st_size > 0


def test_brief_with_mining_only_is_two_pages(tmp_path):
    """The documented "2-page brief": day-resolution data present, no
    cohort section. This is the shape every non-cohort study (e.g. top100)
    actually renders."""
    s = _mined(tmp_path, "solo")
    numbers.build_numbers(s)
    pdf = brief.build(s)
    assert _page_count(pdf) == 2


def test_brief_builds_with_mining_and_cohort_data(tmp_path):
    base = _mined(tmp_path, "base")
    cohort = _mined(tmp_path, "cohort")
    numbers.build_numbers(cohort, baseline=base)
    pdf = brief.build(cohort, baseline_study=base)
    assert pdf.exists()
    assert pdf.stat().st_size > 0
    # Figure 3 must actually be drawn, and from two distinct studies: passing
    # the cohort as its own baseline used to plot one curve against itself.
    assert (cohort.report_dir / "figs" / "brief_cohort_km.png").exists()
    # The cohort section must not overflow onto a 3rd page: it used to spill
    # the last caveat bullet and the footer, which read as the chart
    # crowding the text above it.
    assert _page_count(pdf) == 2


def test_brief_cohort_figure_uses_the_baseline_study(tmp_path, monkeypatch):
    """`_fig_cohort` must be handed the baseline's intervals as the baseline
    series, not a second copy of the cohort's."""
    base = _mined(tmp_path, "base")
    cohort = _mined(tmp_path, "cohort")
    numbers.build_numbers(cohort, baseline=base)

    seen = {}
    real_kept_for = brief._kept_for

    def spy(study):
        seen.setdefault("order", []).append(study.name)
        return real_kept_for(study)

    monkeypatch.setattr(brief, "_kept_for", spy)
    brief.build(cohort, baseline_study=base)
    assert "base" in seen.get("order", []), seen
