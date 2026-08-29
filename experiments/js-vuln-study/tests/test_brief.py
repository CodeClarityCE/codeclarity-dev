"""End-to-end smoke tests for the brief PDF: it must build both with and
without day-resolution mining data and a cohort comparison present."""

from __future__ import annotations

import pytest

from js_vuln_study import brief, numbers
from js_vuln_study.config import Study

from conftest import row, write_manifest, write_tables
from test_numbers import _analysis_row, _study, _vuln_row


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


def test_brief_builds_without_mining_or_cohort_data(tmp_path):
    s = _populated(tmp_path, "solo")
    numbers.build_numbers(s)
    pdf = brief.build(s)
    assert pdf.exists()
    assert pdf.stat().st_size > 0


def test_brief_builds_with_mining_and_cohort_data(tmp_path):
    base = _populated(tmp_path, "base")
    cohort = _populated(tmp_path, "cohort")
    for s in (base, cohort):
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
    numbers.build_numbers(cohort, baseline=base)
    pdf = brief.build(cohort, cohort_study=cohort)
    assert pdf.exists()
    assert pdf.stat().st_size > 0
