"""Unit tests for the blob-flattening collector. Filesystem-only (tmp_path +
trimmed fixtures), no API, no network."""

from __future__ import annotations

import shutil
from pathlib import Path

import pandas as pd
import pytest

from js_vuln_study import collect, manifest
from js_vuln_study.config import Study

from conftest import row, write_manifest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PROJ = "af919e72-f691-47de-a8bf-77a5e7f2cca5"
AID = "7cd19dee-35cd-45fe-a42a-8032e5facec0"


def _study(tmp_path) -> Study:
    d = tmp_path / "s"
    d.mkdir()
    (d / "study.toml").write_text('[study]\nname = "t"\n', encoding="utf-8")
    return Study.load(d)


@pytest.fixture
def study(tmp_path) -> Study:
    s = _study(tmp_path)
    write_manifest(s.manifest_path, [row(project_id=PROJ, analysis_id=AID)])
    raw = s.raw_dir / PROJ / AID
    raw.mkdir(parents=True)
    for name in ("js-sbom.json", "vuln-finder.json"):
        shutil.copy(FIXTURES / name, raw / name)
    return s


# ---- _load_blob --------------------------------------------------------------


def test_load_blob_unwraps_result_envelope(tmp_path):
    import json

    p = tmp_path / "b.json"
    p.write_text(json.dumps({"result": {"workspaces": {}}, "plugin": "js-sbom"}))
    assert collect._load_blob(p) == {"workspaces": {}}


def test_load_blob_returns_raw_without_envelope(tmp_path):
    import json

    p = tmp_path / "b.json"
    p.write_text(json.dumps({"workspaces": {".": {}}}))
    assert collect._load_blob(p) == {"workspaces": {".": {}}}


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
        v["OSVMatch"] = {"Vulnerability": {"published": "osv-pub", "modified": "osv-mod", "withdrawn": "osv-wd"}}
    if gcve:
        v["GCVEMatch"] = {"Vulnerability": {"datePublished": "gcve-pub", "dateUpdated": "gcve-mod"}}
    return v


def test_disclosure_dates_prefers_nvd_over_osv_over_gcve():
    published, modified, withdrawn = collect._disclosure_dates(_dated(nvd=True, osv=True, gcve=True))
    assert (published, modified) == ("nvd-pub", "nvd-mod")
    assert withdrawn == "osv-wd"


def test_disclosure_dates_falls_back_to_osv_then_gcve():
    assert collect._disclosure_dates(_dated(osv=True, gcve=True))[:2] == ("osv-pub", "osv-mod")
    assert collect._disclosure_dates(_dated(gcve=True))[:2] == ("gcve-pub", "gcve-mod")


def test_disclosure_dates_empty():
    assert collect._disclosure_dates({}) == (None, None, None)


# ---- build_tables ----------------------------------------------------------------


def test_build_tables_analyses_metrics(study):
    collect.build_tables(study)
    df = pd.read_parquet(study.tables_dir / "analyses.parquet")
    assert len(df) == 1
    r = df.iloc[0]
    assert r["analysis_id"] == AID
    assert r["project_id"] == PROJ
    assert r["total_dependencies"] == 3
    assert r["direct_dependencies"] == 2
    assert r["transitive_dependencies"] == 1
    assert r["package_manager"] == "PNPM"
    assert r["total_vulnerabilities"] == 3
    assert r["vulnerable_dependencies"] == 3
    assert r["direct_vulnerabilities"] == 1
    assert r["transitive_vulnerabilities"] == 2
    assert r["n_critical"] == 1
    assert r["n_high"] == 1
    assert r["n_medium"] == 1


def test_build_tables_vuln_rows_and_winning_source(study):
    collect.build_tables(study)
    df = pd.read_parquet(study.tables_dir / "vulns.parquet").set_index("vulnerability_id")
    assert len(df) == 3
    v1 = df.loc["CVE-2024-27949"]
    assert v1["winning_source"] == "GCVE"
    assert v1["conflict_flag"] == "MATCH_POSSIBLE_INCORRECT"
    assert v1["affected_dependency"] == "sirv"
    assert v1["severity_class"] == "MEDIUM"
    assert bool(v1["direct_dependency"]) is True
    v2 = df.loc["CVE-2015-8315"]
    assert v2["winning_source"] == "NVD"
    assert bool(v2["direct_dependency"]) is False
    v3 = df.loc["CVE-2025-30208"]
    assert pd.isna(v3["winning_source"]) and pd.isna(v3["conflict_flag"])


def test_build_tables_epss_present_and_absent(study):
    collect.build_tables(study)
    df = pd.read_parquet(study.tables_dir / "vulns.parquet").set_index("vulnerability_id")
    assert df.loc["CVE-2024-27949", "epss_score"] == 0.00042
    assert df.loc["CVE-2024-27949", "epss_percentile"] == 0.113
    assert pd.isna(df.loc["CVE-2015-8315", "epss_score"])
    assert pd.isna(df.loc["CVE-2025-30208", "epss_score"])


def test_build_tables_vuln_disclosure_dates(study):
    collect.build_tables(study)
    df = pd.read_parquet(study.tables_dir / "vulns.parquet").set_index("vulnerability_id")
    assert df.loc["CVE-2024-27949", "published_date"].startswith("2024-03-01")
    assert df.loc["CVE-2015-8315", "published_date"] == "2016-01-08T19:59:00.000"
    assert df.loc["CVE-2025-30208", "withdrawn_date"] == "2025-04-02T00:00:00Z"


def test_build_tables_no_dependencies_parquet(study):
    collect.build_tables(study)
    assert not (study.tables_dir / "dependencies.parquet").exists()


def test_build_tables_run_id_column(tmp_path):
    s = _study(tmp_path)
    write_manifest(s.manifest_path, [row(project_id=PROJ, analysis_id=AID, run_id="abc")])
    raw = s.raw_dir / PROJ / AID
    raw.mkdir(parents=True)
    for name in ("js-sbom.json", "vuln-finder.json"):
        shutil.copy(FIXTURES / name, raw / name)
    collect.build_tables(s)
    df = pd.read_parquet(s.tables_dir / "analyses.parquet")
    assert df.iloc[0]["run_id"] == "abc"


def test_build_tables_skips_non_done_rows(study):
    rows = [
        row(project_id=PROJ, analysis_id=AID, state="done"),
        row(project_id=PROJ, analysis_id="b" * 36, state="failed", error="stall"),
        row(project_id=None, analysis_id=None, state="skipped"),
    ]
    write_manifest(study.manifest_path, rows)
    collect.build_tables(study)
    df = pd.read_parquet(study.tables_dir / "analyses.parquet")
    assert len(df) == 1


def test_build_tables_tolerates_missing_blobs(tmp_path):
    s = _study(tmp_path)
    write_manifest(s.manifest_path, [row(project_id=PROJ, analysis_id=AID)])
    collect.build_tables(s)
    df = pd.read_parquet(s.tables_dir / "analyses.parquet")
    assert len(df) == 1
    assert df.iloc[0]["total_dependencies"] == 0
    assert df.iloc[0]["total_vulnerabilities"] == 0


# ---- coverage_report ---------------------------------------------------------


def test_coverage_report_buckets_sum_to_manifest_rows(tmp_path):
    s = _study(tmp_path)
    rows = [
        row(state="done"),
        row(state="done", snapshot_date="2024-01-01"),
        row(state="failed", snapshot_date="2024-04-01", error="boom"),
        row(state="pending", snapshot_date="2024-07-01"),
        row(state="skipped", git_url="https://github.com/dead/repo", snapshot_date="*", project_id=None, analysis_id=None, error="import"),
    ]
    write_manifest(s.manifest_path, rows)
    counts = collect.coverage_report(s)
    assert counts == {"done": 2, "failed": 1, "pending": 1, "skipped": 1}
    assert sum(counts.values()) == len(rows)


def test_coverage_report_writes_dropped_csv(tmp_path):
    s = _study(tmp_path)
    write_manifest(s.manifest_path, [
        row(state="done"),
        row(state="failed", snapshot_date="2024-01-01", error="clean"),
        row(state="skipped", snapshot_date="2024-04-01", error="stall", project_id=None, analysis_id=None),
    ])
    collect.coverage_report(s)
    dropped = pd.read_csv(s.tables_dir / "coverage_dropped.csv")
    assert len(dropped) == 2
    assert set(dropped["state"]) == {"failed", "skipped"}


def test_coverage_report_no_dropped_no_csv(tmp_path):
    s = _study(tmp_path)
    write_manifest(s.manifest_path, [row(state="done")])
    assert collect.coverage_report(s) == {"done": 1}
    assert not (s.tables_dir / "coverage_dropped.csv").exists()


def test_coverage_report_empty_manifest(tmp_path):
    s = _study(tmp_path)
    assert collect.coverage_report(s) == {}


# ---- run_meta copy -------------------------------------------------------------


def _meta(sources: dict | None, run_id="r") -> dict:
    return {"run_id": run_id, "knowledge": {"knowledge_sources": sources}}


def test_copy_run_meta_copies_latest_record(study):
    import json

    metas = [_meta({"nvd": "2026-01-01"}), _meta({"nvd": "2026-01-01"}, run_id="last")]
    with study.run_meta_path.open("w", encoding="utf-8") as f:
        for m in metas:
            f.write(json.dumps(m) + "\n")
    collect.build_tables(study)
    copied = __import__("json").loads((study.tables_dir / "run_meta.json").read_text())
    assert copied["run_id"] == "last"


def test_copy_run_meta_warns_on_mixed_knowledge_snapshots(study, caplog):
    import json

    with study.run_meta_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps(_meta({"nvd": "2026-01-01"})) + "\n")
        f.write(json.dumps(_meta({"nvd": "2026-06-01"})) + "\n")
    with caplog.at_level("WARNING"):
        collect.build_tables(study)
    assert any("distinct knowledge-DB snapshots" in r.message for r in caplog.records)


def test_copy_run_meta_warns_when_missing(study, caplog):
    with caplog.at_level("WARNING"):
        collect.build_tables(study)
    assert any("provenance unknown" in r.message for r in caplog.records)
    assert not (study.tables_dir / "run_meta.json").exists()
