"""Unit tests for the clone-reclamation module.

Everything here is filesystem-only (tmp_path) — no API, no network.
Run with: cd experiments/js-vuln-study && .venv/bin/python -m pytest tests/ -q
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from js_vuln_study import reclaim  # noqa: E402
from js_vuln_study.orchestrator import _active_leaves, _leaf_key  # noqa: E402

ORG = "e8467209-05fc-40b5-8217-a9127d1a14a4"
PROJ = "af919e72-f691-47de-a8bf-77a5e7f2cca5"
PROJ2 = "bf919e72-f691-47de-a8bf-77a5e7f2cca6"


@pytest.fixture
def clone_tree(tmp_path, monkeypatch):
    """A fake clone root with two projects, wired up as JS_VULN_CLONE_DIR."""
    root = tmp_path / "private"
    for project, leaves in ((PROJ, ["main", "a" * 40]), (PROJ2, ["main"])):
        for leaf in leaves:
            d = root / ORG / "projects" / project / leaf
            d.mkdir(parents=True)
            (d / "package.json").write_text("{}" * 100)
    (root / ".DS_Store").write_text("junk")
    monkeypatch.setenv(reclaim.CLONE_DIR_ENV, str(root))
    reclaim.reset_cache()
    yield root
    reclaim.reset_cache()


# ---- clone_root ------------------------------------------------------------


def test_clone_root_honours_env_override(clone_tree):
    assert reclaim.clone_root() == clone_tree.resolve()


def test_clone_root_missing_disables_and_warns_once(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv(reclaim.CLONE_DIR_ENV, str(tmp_path / "nope"))
    reclaim.reset_cache()
    with caplog.at_level("WARNING"):
        assert reclaim.clone_root() is None
        assert reclaim.clone_root() is None  # memoised
    warnings = [r for r in caplog.records if "reclamation disabled" in r.message]
    assert len(warnings) == 1


def test_reclaim_is_a_noop_when_root_missing(tmp_path, monkeypatch):
    monkeypatch.setenv(reclaim.CLONE_DIR_ENV, str(tmp_path / "nope"))
    reclaim.reset_cache()
    assert reclaim.reclaim_leaf(ORG, PROJ, "main") == 0
    assert reclaim.sweep(ORG, set()).scanned == 0


# ---- leaf_for --------------------------------------------------------------


@pytest.mark.parametrize(
    "commit,branch,expected",
    [
        ("abc1234", "main", "abc1234"),  # commit wins
        ("", "main", "main"),            # empty commit -> branch (client.py:281)
        (None, "main", "main"),
        (" ", "main", "main"),           # downloader treats " " as absent too
        (None, None, None),
    ],
)
def test_leaf_for(commit, branch, expected):
    assert reclaim.leaf_for(commit, branch) == expected


# ---- path safety -----------------------------------------------------------


@pytest.mark.parametrize("segment", ["..", "../..", ".", "", "\0"])
def test_safe_join_rejects_empty_or_dotdot(tmp_path, segment):
    """Segments that sanitise to nothing (or to '..') are refused outright."""
    with pytest.raises(ValueError):
        reclaim._safe_join(tmp_path, segment)


@pytest.mark.parametrize("segment", ["/etc", "~", "../evil", "a/../../b"])
def test_safe_join_confines_to_base(tmp_path, segment):
    """Anything else is reduced to its basename and stays under the root."""
    joined = reclaim._safe_join(tmp_path, segment)
    assert joined.parent == tmp_path.resolve()


def test_safe_join_rejects_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="traversal"):
        reclaim._safe_join(root, "escape")


@pytest.mark.parametrize("leaf,ok", [
    ("main", True),
    ("a" * 40, True),
    ("abc1234", True),
    ("release/1.x", False),  # nested branch dirs are refused, not modelled
    ("..", False),
    ("-rf", False),
    ("", False),
])
def test_is_leaf_shaped(leaf, ok):
    assert reclaim.is_leaf_shaped(leaf) is ok


def test_is_uuid():
    assert reclaim.is_uuid(ORG)
    assert not reclaim.is_uuid("not-a-uuid")
    assert not reclaim.is_uuid(None)


# ---- reclaim_leaf ----------------------------------------------------------


def test_reclaim_leaf_deletes_and_reports_bytes(clone_tree):
    target = clone_tree / ORG / "projects" / PROJ / "main"
    freed = reclaim.reclaim_leaf(ORG, PROJ, "main")
    assert freed > 0
    assert not target.exists()
    # sibling leaf and the other project are untouched
    assert (clone_tree / ORG / "projects" / PROJ / ("a" * 40)).is_dir()
    assert (clone_tree / ORG / "projects" / PROJ2 / "main").is_dir()


def test_reclaim_leaf_missing_dir_is_zero(clone_tree):
    assert reclaim.reclaim_leaf(ORG, PROJ, "nonexistent-branch") == 0


def test_reclaim_leaf_refuses_bad_shape(clone_tree):
    assert reclaim.reclaim_leaf("not-a-uuid", PROJ, "main") == 0
    assert (clone_tree / ORG / "projects" / PROJ / "main").is_dir()


def test_reclaim_leaf_dry_run_keeps_dir(clone_tree):
    target = clone_tree / ORG / "projects" / PROJ / "main"
    assert reclaim.reclaim_leaf(ORG, PROJ, "main", dry_run=True) > 0
    assert target.is_dir()


def test_reclaim_prunes_empty_parents(clone_tree):
    reclaim.reclaim_leaf(ORG, PROJ2, "main")
    assert not (clone_tree / ORG / "projects" / PROJ2).exists()
    # the org level survives while another project still has clones
    assert (clone_tree / ORG / "projects" / PROJ).is_dir()


# ---- sweep -----------------------------------------------------------------


def test_sweep_deletes_all_when_nothing_kept(clone_tree):
    rep = reclaim.sweep(ORG, set())
    assert rep.scanned == 3
    assert len(rep.deleted) == 3
    assert rep.bytes_freed > 0
    assert not (clone_tree / ORG).exists()  # empty org dir pruned


def test_sweep_honours_keep_set(clone_tree):
    rep = reclaim.sweep(ORG, {(PROJ, "main")})
    assert len(rep.deleted) == 2
    assert (clone_tree / ORG / "projects" / PROJ / "main").is_dir()
    assert rep.kept_by_reason() == {"in-use": 1}


def test_sweep_dry_run_reports_without_deleting(clone_tree):
    dry = reclaim.sweep(ORG, set(), dry_run=True)
    assert (clone_tree / ORG / "projects" / PROJ / "main").is_dir()
    wet = reclaim.sweep(ORG, set())
    assert dry.bytes_freed == wet.bytes_freed
    assert len(dry.deleted) == len(wet.deleted)


def test_sweep_is_idempotent(clone_tree):
    reclaim.sweep(ORG, set())
    second = reclaim.sweep(ORG, set())
    assert second.scanned == 0 and second.bytes_freed == 0


def test_sweep_tolerates_stray_files_and_odd_dirs(clone_tree):
    (clone_tree / ORG / "projects" / "not-a-uuid").mkdir()
    (clone_tree / ORG / "projects" / PROJ / "release").mkdir()
    rep = reclaim.sweep(ORG, set())
    assert (clone_tree / ORG / "projects" / "not-a-uuid").is_dir()
    assert "shape-rejected" in rep.kept_by_reason()
    assert (clone_tree / ".DS_Store").exists()


def test_sweep_ignores_other_orgs(clone_tree):
    other = "cf919e72-f691-47de-a8bf-77a5e7f2cca7"
    foreign = clone_tree / other / "projects" / PROJ / "main"
    foreign.mkdir(parents=True)
    reclaim.sweep(ORG, set())
    assert foreign.is_dir()


# ---- in-use guard (orchestrator adapter) -----------------------------------


def _rec(status: str, project_id: str = PROJ, commit=None, branch="main") -> dict:
    return {
        "status": status, "project_id": project_id,
        "commit_hash": commit, "branch": branch,
    }


def test_leaf_key_matches_reclaim_layout():
    assert _leaf_key(_rec("submitted", commit="abc1234")) == (PROJ, "abc1234")
    assert _leaf_key(_rec("submitted")) == (PROJ, "main")
    assert _leaf_key({"status": "skipped", "project_id": None}) is None


def test_shared_leaf_is_held_until_last_record_terminates(clone_tree, monkeypatch):
    from js_vuln_study import orchestrator

    records = [_rec("submitted"), _rec("submitted")]
    active = _active_leaves(records)
    assert active[(PROJ, "main")] == 2

    target = clone_tree / ORG / "projects" / PROJ / "main"
    # first record goes terminal — the other still holds the leaf
    assert orchestrator._reclaim_for_record(ORG, records[0], active) == 0
    assert target.is_dir()
    # second one releases it
    assert orchestrator._reclaim_for_record(ORG, records[1], active) > 0
    assert not target.exists()


def test_active_leaves_ignores_settled_records():
    records = [_rec("submitted"), _rec("completed"), _rec("failed", project_id=PROJ2)]
    assert _active_leaves(records) == Counter({(PROJ, "main"): 1})
