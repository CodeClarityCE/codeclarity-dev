"""Unit tests for the blob-flattening collector.

Everything here is filesystem-only (tmp_path + trimmed fixtures) — no API, no
network. Run with: cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import collect  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

PROJ = "af919e72-f691-47de-a8bf-77a5e7f2cca5"
AID = "7cd19dee-35cd-45fe-a42a-8032e5facec0"


def _row(status: str = "completed", **over) -> dict:
    rec = {
        "npm_name": "@vue/runtime-core",
        "tier": "top-100",
        "rank": 0,
        "git_url": "https://github.com/vuejs/core",
        "branch": "main",
        "snapshot_date": "HEAD",
        "commit_hash": "a" * 40,
        "committed_at": "2026-07-01T00:00:00Z",
        "project_id": PROJ,
        "analysis_id": AID,
        "status": status,
        "error": None,
    }
    rec.update(over)
    return rec


def _write_manifest(data_dir: Path, rows: list[dict]) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "manifest.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


@pytest.fixture
def data_dir(tmp_path) -> Path:
    """A data dir with one completed analysis backed by the trimmed fixtures."""
    d = tmp_path / "data"
    _write_manifest(d, [_row()])
    raw = d / "raw" / PROJ / AID
    raw.mkdir(parents=True)
    for name in ("js-sbom.json", "vuln-finder.json", "license-finder.json"):
        shutil.copy(FIXTURES / name, raw / name)
    return d


# ---- _load_blob --------------------------------------------------------------


def test_load_blob_unwraps_result_envelope(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"result": {"workspaces": {}}, "plugin": "js-sbom"}))
    assert collect._load_blob(p) == {"workspaces": {}}


def test_load_blob_returns_raw_without_envelope(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"workspaces": {".": {}}}))
    assert collect._load_blob(p) == {"workspaces": {".": {}}}


def test_load_blob_non_dict_result_key_is_not_unwrapped(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"result": [1, 2]}))
    assert collect._load_blob(p) == {"result": [1, 2]}


def test_load_blob_missing_file_is_none(tmp_path):
    assert collect._load_blob(tmp_path / "nope.json") is None


def test_load_blob_malformed_json_warns_and_returns_none(tmp_path, caplog):
    p = tmp_path / "b.json"
    p.write_text("{not json")
    with caplog.at_level("WARNING"):
        assert collect._load_blob(p) is None
    assert any("invalid json" in r.message for r in caplog.records)


# ---- _disclosure_dates ---------------------------------------------------------


def _dated(nvd=False, osv=False, gcve=False) -> dict:
    v: dict = {}
    if nvd:
        v["NVDMatch"] = {"Vulnerability": {"Published": "nvd-pub", "LastModified": "nvd-mod"}}
    if osv:
        v["OSVMatch"] = {"Vulnerability": {
            "published": "osv-pub", "modified": "osv-mod", "withdrawn": "osv-wd",
        }}
    if gcve:
        v["GCVEMatch"] = {"Vulnerability": {"datePublished": "gcve-pub", "dateUpdated": "gcve-mod"}}
    return v


def test_disclosure_dates_prefers_nvd_over_osv_over_gcve():
    published, modified, withdrawn = collect._disclosure_dates(_dated(nvd=True, osv=True, gcve=True))
    assert (published, modified) == ("nvd-pub", "nvd-mod")
    assert withdrawn == "osv-wd"  # NVD has no withdrawn concept


def test_disclosure_dates_falls_back_to_osv_then_gcve():
    assert collect._disclosure_dates(_dated(osv=True, gcve=True))[:2] == ("osv-pub", "osv-mod")
    assert collect._disclosure_dates(_dated(gcve=True))[:2] == ("gcve-pub", "gcve-mod")


def test_disclosure_dates_top_level_fallback_and_empty():
    v = {"published_date": "top-pub", "modified_date": "top-mod", "withdrawn_date": "top-wd"}
    assert collect._disclosure_dates(v) == ("top-pub", "top-mod", "top-wd")
    assert collect._disclosure_dates({}) == (None, None, None)


# ---- step timings ------------------------------------------------------------

# Shape of a live terminal analysis doc: the dispatcher's Go Step struct has no
# JSON tags, so steps marshal as Name/Status/Started_on/Ended_on (RFC3339Nano).
ANALYSIS_DOC = {
    "id": AID,
    "status": "completed",
    "created_on": "2026-08-03T11:00:41.331Z",
    "steps": [
        [
            {"Name": "js-sbom", "Status": "success",
             "Started_on": "2026-08-03T11:01:04.768355005Z",
             "Ended_on": "2026-08-03T11:01:05.861302922Z"},
        ],
        [
            {"Name": "vuln-finder", "Status": "success",
             "Started_on": "2026-08-03T11:01:22.335175638Z",
             "Ended_on": "2026-08-03T11:01:27.503752127Z"},
            {"Name": "license-finder", "Status": "success",
             "Started_on": "2026-08-03T11:02:18.021660761Z",
             "Ended_on": "2026-08-03T11:02:32.535417796Z"},
        ],
    ],
}


def test_step_timings_flattens_live_step_shape():
    cols = collect._step_timings(ANALYSIS_DOC)
    assert cols["step_js_sbom_started"] == "2026-08-03T11:01:04.768355005Z"
    assert cols["step_js_sbom_ended"] == "2026-08-03T11:01:05.861302922Z"
    assert cols["step_js_sbom_duration_s"] == pytest.approx(1.0929, abs=1e-3)
    assert cols["step_vuln_finder_duration_s"] == pytest.approx(5.1686, abs=1e-3)
    assert cols["step_license_finder_duration_s"] == pytest.approx(14.5138, abs=1e-3)


def test_step_timings_tolerates_lowercase_and_missing_fields():
    doc = {"steps": [[
        {"name": "js-sbom", "started_on": "2026-08-03T11:01:04Z"},  # no ended_on
        {"Status": "success"},  # no name at all -> skipped
        "not-a-dict",
    ], "not-a-stage"]}
    cols = collect._step_timings(doc)
    assert cols == {
        "step_js_sbom_started": "2026-08-03T11:01:04Z",
        "step_js_sbom_ended": None,
        "step_js_sbom_duration_s": None,
    }


def test_step_timings_non_dict_inputs():
    assert collect._step_timings(None) == {}
    assert collect._step_timings([]) == {}
    assert collect._step_timings({"steps": None}) == {}


def test_duration_seconds_invalid_inputs():
    assert collect._duration_seconds(None, "2026-08-03T11:01:05Z") is None
    assert collect._duration_seconds("not a date", "2026-08-03T11:01:05Z") is None
    assert collect._duration_seconds("2026-08-03T11:01:04Z", "2026-08-03T11:01:05Z") == 1.0


# ---- build_tables ----------------------------------------------------------------


def test_build_tables_analyses_metrics(data_dir):
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    assert len(df) == 1
    row = df.iloc[0]
    assert row["analysis_id"] == AID
    assert row["project_id"] == PROJ
    assert row["total_dependencies"] == 3
    assert row["direct_dependencies"] == 2
    assert row["transitive_dependencies"] == 1
    assert row["dev_dependencies"] == 2
    assert row["prod_dependencies"] == 1
    assert row["package_manager"] == "PNPM"
    assert row["total_vulnerabilities"] == 3
    assert row["vulnerable_dependencies"] == 3
    assert row["direct_vulnerabilities"] == 1
    assert row["transitive_vulnerabilities"] == 2
    assert row["n_critical"] == 1
    assert row["n_high"] == 1
    assert row["n_medium"] == 1
    assert row["n_low"] == 0
    assert row["n_none"] == 0


def test_build_tables_vuln_rows_and_winning_source(data_dir):
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "vulns.parquet").set_index("vulnerability_id")
    assert len(df) == 3

    v1 = df.loc["CVE-2024-27949"]
    # Regression: winning_source comes from Conflict.ConflictWinner (the Go
    # struct has no JSON tags, so the fields marshal PascalCase).
    assert v1["winning_source"] == "GCVE"
    assert v1["conflict_flag"] == "MATCH_POSSIBLE_INCORRECT"
    assert v1["affected_dependency"] == "sirv"
    assert v1["affected_version"] == "3.0.2"
    assert v1["severity_class"] == "MEDIUM"
    assert v1["severity_score"] == 5.4
    assert bool(v1["direct_dependency"]) is True

    v2 = df.loc["CVE-2015-8315"]
    assert v2["winning_source"] == "NVD"
    assert bool(v2["direct_dependency"]) is False

    v3 = df.loc["CVE-2025-30208"]
    assert pd.isna(v3["winning_source"]) and pd.isna(v3["conflict_flag"])


def test_build_tables_epss_present_and_absent(data_dir):
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "vulns.parquet").set_index("vulnerability_id")
    # EPSS arrives as vulnerability["EPSS"]["Score"/"Percentile"].
    assert df.loc["CVE-2024-27949", "epss_score"] == 0.00042
    assert df.loc["CVE-2024-27949", "epss_percentile"] == 0.113
    # Missing EPSS key and explicit EPSS: null both flatten to null.
    assert pd.isna(df.loc["CVE-2015-8315", "epss_score"])
    assert pd.isna(df.loc["CVE-2015-8315", "epss_percentile"])
    assert pd.isna(df.loc["CVE-2025-30208", "epss_score"])


def test_build_tables_vuln_disclosure_dates(data_dir):
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "vulns.parquet").set_index("vulnerability_id")
    # GCVE-only vuln takes GCVE dates; NVD+OSV vuln prefers NVD; OSV-only keeps withdrawn.
    assert df.loc["CVE-2024-27949", "published_date"].startswith("2024-03-01")
    assert df.loc["CVE-2015-8315", "published_date"] == "2016-01-08T19:59:00.000"
    assert df.loc["CVE-2025-30208", "withdrawn_date"] == "2025-04-02T00:00:00Z"


def test_build_tables_dependencies_table(data_dir):
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "dependencies.parquet")
    assert len(df) == 3
    by_name = df.set_index("name")
    assert bool(by_name.loc["ms", "transitive"]) is True
    assert bool(by_name.loc["ms", "direct"]) is False
    assert bool(by_name.loc["sirv", "direct"]) is True
    assert bool(by_name.loc["vite", "prod"]) is True
    assert by_name.loc["vite", "version"] == "5.4.0"
    assert set(df["package_manager"]) == {"PNPM"}
    assert list(by_name.loc["sirv", "licenses"]) == ["MIT"]
    assert list(by_name.loc["ms", "licenses"]) == []  # null Licenses flattens to []


def test_include_deps_false_skips_table_but_keeps_counts(data_dir):
    collect.build_tables(data_dir, include_deps=False)
    tables = data_dir / "tables"
    assert not (tables / "dependencies.parquet").exists()
    df = pd.read_parquet(tables / "analyses.parquet")
    assert df.iloc[0]["total_dependencies"] == 3
    assert df.iloc[0]["direct_dependencies"] == 2
    assert (tables / "vulns.parquet").exists()


def test_build_tables_skips_non_completed_rows(data_dir):
    rows = [
        _row(),
        _row(status="failed", analysis_id="b" * 36, error="stall"),
        _row(status="skipped", project_id=None, analysis_id=None),
    ]
    _write_manifest(data_dir, rows)
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    assert len(df) == 1


def test_build_tables_tolerates_missing_blobs(tmp_path):
    d = tmp_path / "data"
    _write_manifest(d, [_row()])  # completed, but no raw/ blobs at all
    collect.build_tables(d)
    df = pd.read_parquet(d / "tables" / "analyses.parquet")
    assert len(df) == 1
    assert df.iloc[0]["total_dependencies"] == 0
    assert df.iloc[0]["total_vulnerabilities"] == 0


def test_build_tables_exports_step_timings_and_manifest_stamps(data_dir):
    (data_dir / "raw" / PROJ / AID / "analysis.json").write_text(json.dumps(ANALYSIS_DOC))
    _write_manifest(data_dir, [_row(
        submitted_at="2026-08-03T11:00:41Z", terminal_at="2026-08-03T11:02:33Z",
    )])
    collect.build_tables(data_dir)
    row = pd.read_parquet(data_dir / "tables" / "analyses.parquet").iloc[0]
    assert row["submitted_at"] == "2026-08-03T11:00:41Z"
    assert row["terminal_at"] == "2026-08-03T11:02:33Z"
    assert row["step_js_sbom_started"] == "2026-08-03T11:01:04.768355005Z"
    assert row["step_js_sbom_duration_s"] == pytest.approx(1.0929, abs=1e-3)
    assert row["step_license_finder_ended"] == "2026-08-03T11:02:32.535417796Z"
    # downloader/queue wait is derivable: submit -> first step dispatch
    wait = (pd.Timestamp(row["step_js_sbom_started"]) - pd.Timestamp(row["submitted_at"]))
    assert wait.total_seconds() == pytest.approx(23.768, abs=1e-2)
    # the timing columns must not leak into the per-vuln/per-dep tables
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    assert "step_js_sbom_started" not in vulns.columns
    assert "submitted_at" not in vulns.columns


def test_build_tables_tolerates_pre_telemetry_rows(data_dir):
    # Manifest row without submitted_at/terminal_at and no analysis.json —
    # exactly what an old run's data looks like.
    collect.build_tables(data_dir)
    row = pd.read_parquet(data_dir / "tables" / "analyses.parquet").iloc[0]
    assert pd.isna(row["submitted_at"])
    assert pd.isna(row["terminal_at"])
    assert "step_js_sbom_started" not in row.index


def test_build_tables_mixed_telemetry_rows(data_dir):
    # One row with analysis.json, one completed row without: the timing columns
    # exist and are NaN for the older row.
    (data_dir / "raw" / PROJ / AID / "analysis.json").write_text(json.dumps(ANALYSIS_DOC))
    aid2 = "8dd19dee-35cd-45fe-a42a-8032e5facec1"
    (data_dir / "raw" / PROJ / aid2).mkdir(parents=True)
    _write_manifest(data_dir, [
        _row(submitted_at="2026-08-03T11:00:41Z", terminal_at="2026-08-03T11:02:33Z"),
        _row(analysis_id=aid2, snapshot_date="2024-01-01"),
    ])
    collect.build_tables(data_dir)
    df = pd.read_parquet(data_dir / "tables" / "analyses.parquet").set_index("analysis_id")
    assert df.loc[AID, "step_js_sbom_duration_s"] == pytest.approx(1.0929, abs=1e-3)
    assert pd.isna(df.loc[aid2, "step_js_sbom_duration_s"])
    assert pd.isna(df.loc[aid2, "submitted_at"])


# ---- coverage_report ---------------------------------------------------------


def test_coverage_report_buckets_sum_to_manifest_rows(tmp_path):
    d = tmp_path / "data"
    rows = [
        _row(),
        _row(status="success", snapshot_date="2024-01-01"),
        _row(status="failure", snapshot_date="2024-04-01", error="boom"),
        _row(status="submitted", snapshot_date="2024-07-01"),
        _row(status="failed-submit", snapshot_date="2024-10-01", error="500"),
        _row(status="skipped", git_url="https://github.com/dead/repo",
             snapshot_date="*", project_id=None, analysis_id=None, error="import"),
    ]
    _write_manifest(d, rows)
    counts = collect.coverage_report(d)
    assert counts == {
        "completed": 2, "failed": 1, "in-flight": 1, "failed-submit": 1, "skipped": 1,
    }
    assert sum(counts.values()) == len(rows)


def test_coverage_report_dedups_reemitted_skip_rows(tmp_path):
    d = tmp_path / "data"
    skip = _row(status="skipped", snapshot_date="*", project_id=None,
                analysis_id=None, error="transient")
    _write_manifest(d, [skip, skip, _row()])
    counts = collect.coverage_report(d)
    assert counts == {"skipped": 1, "completed": 1}


def test_coverage_report_writes_dropped_csv(tmp_path):
    d = tmp_path / "data"
    _write_manifest(d, [
        _row(),
        _row(status="cancelled", snapshot_date="2024-01-01", error="clean"),
        _row(status="failed", snapshot_date="2024-04-01", error="stall"),
    ])
    collect.coverage_report(d)
    dropped = pd.read_csv(d / "tables" / "coverage_dropped.csv")
    assert len(dropped) == 2
    assert set(dropped["status"]) == {"cancelled", "failed"}


def test_coverage_report_no_dropped_no_csv(tmp_path):
    d = tmp_path / "data"
    _write_manifest(d, [_row()])
    assert collect.coverage_report(d) == {"completed": 1}
    assert not (d / "tables" / "coverage_dropped.csv").exists()


def test_coverage_report_empty_manifest(tmp_path):
    assert collect.coverage_report(tmp_path) == {}


# ---- run_meta copy -------------------------------------------------------------


def _meta(sources: dict | None) -> dict:
    return {"run_id": "r", "knowledge": {"knowledge_sources": sources}}


def test_copy_run_meta_copies_latest_record(data_dir):
    metas = [_meta({"nvd": "2026-01-01"}), _meta({"nvd": "2026-01-01"}) | {"run_id": "last"}]
    with (data_dir / "run_meta.jsonl").open("w", encoding="utf-8") as f:
        for m in metas:
            f.write(json.dumps(m) + "\n")
    collect.build_tables(data_dir)
    copied = json.loads((data_dir / "tables" / "run_meta.json").read_text())
    assert copied["run_id"] == "last"


def test_copy_run_meta_warns_on_mixed_knowledge_snapshots(data_dir, caplog):
    with (data_dir / "run_meta.jsonl").open("w", encoding="utf-8") as f:
        f.write(json.dumps(_meta({"nvd": "2026-01-01"})) + "\n")
        f.write(json.dumps(_meta({"nvd": "2026-06-01"})) + "\n")
    with caplog.at_level("WARNING"):
        collect.build_tables(data_dir)
    assert any("distinct knowledge-DB snapshots" in r.message for r in caplog.records)


def test_copy_run_meta_warns_when_missing(data_dir, caplog):
    with caplog.at_level("WARNING"):
        collect.build_tables(data_dir)
    assert any("provenance unknown" in r.message for r in caplog.records)
    assert not (data_dir / "tables" / "run_meta.json").exists()
