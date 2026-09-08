from __future__ import annotations

from js_vuln_study.config import DEFAULTS, Study, expand_grid

# The literal grid the harness used before this simplification: quarterly
# 2022-2023, monthly 2024-01 through 2026-08.
LEGACY_SNAPSHOT_DATES = [
    "2022-01-01", "2022-04-01", "2022-07-01", "2022-10-01",
    "2023-01-01", "2023-04-01", "2023-07-01", "2023-10-01",
    "2024-01-01", "2024-02-01", "2024-03-01", "2024-04-01",
    "2024-05-01", "2024-06-01", "2024-07-01", "2024-08-01",
    "2024-09-01", "2024-10-01", "2024-11-01", "2024-12-01",
    "2025-01-01", "2025-02-01", "2025-03-01", "2025-04-01",
    "2025-05-01", "2025-06-01", "2025-07-01", "2025-08-01",
    "2025-09-01", "2025-10-01", "2025-11-01", "2025-12-01",
    "2026-01-01", "2026-02-01", "2026-03-01", "2026-04-01",
    "2026-05-01", "2026-06-01", "2026-07-01", "2026-08-01",
]


def test_expand_grid_default_matches_legacy_40_date_list():
    assert expand_grid(DEFAULTS["grid"]) == LEGACY_SNAPSHOT_DATES


def test_expand_grid_quarterly_only():
    assert expand_grid({"quarterly": ["2022-01-01", "2022-10-01"], "monthly": None}) == [
        "2022-01-01", "2022-04-01", "2022-07-01", "2022-10-01",
    ]


def test_expand_grid_monthly_only():
    assert expand_grid({"quarterly": None, "monthly": ["2024-11-01", "2025-02-01"]}) == [
        "2024-11-01", "2024-12-01", "2025-01-01", "2025-02-01",
    ]


def test_study_load_defaults_from_directory_name(tmp_path):
    d = tmp_path / "my-study"
    d.mkdir()
    study = Study.load(d)
    assert study.name == "my-study"
    assert study.org_name == "js-vuln-study-my-study"
    assert study.analyzer_name == "js-vuln-study-v2"
    assert study.snapshots is True
    assert study.retries == 2
    assert study.knowledge_asof is None
    assert study.grid == expand_grid(DEFAULTS["grid"])


def test_study_load_overrides_from_toml(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "study.toml").write_text(
        '[study]\nname = "custom"\nknowledge_asof = "2026-08-03"\nretries = 5\n'
        '[codeclarity]\norg = "my-org"\n',
        encoding="utf-8",
    )
    study = Study.load(d)
    assert study.name == "custom"
    assert study.knowledge_asof == "2026-08-03"
    assert study.retries == 5
    assert study.org_name == "my-org"  # explicit org wins over the derived default


def test_study_frozen_from_resolves_relative_to_study_dir(tmp_path):
    (tmp_path / "top100").mkdir()
    (tmp_path / "top100" / "manifest.jsonl").write_text("", encoding="utf-8")
    rung = tmp_path / "rung"
    rung.mkdir()
    (rung / "study.toml").write_text('[study]\nfrozen_from = "../top100/manifest.jsonl"\n', encoding="utf-8")
    study = Study.load(rung)
    assert study.frozen_from == (tmp_path / "top100" / "manifest.jsonl").resolve()


def test_study_paths_are_under_the_study_dir(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    study = Study.load(d)
    assert study.manifest_path == d / "manifest.jsonl"
    assert study.tables_dir == d / "tables"
    assert study.raw_dir == d / "raw"
    assert study.report_dir == d / "report"
