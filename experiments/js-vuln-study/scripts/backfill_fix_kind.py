"""Backfill fix_kind / fix_to_version onto an existing remediation_events
parquet, from the cached lockfile blobs — no re-mining.

The miner now emits both columns natively (remediation.classify_fix inside
mine_unit); this script retro-classifies parquets mined before that change,
and doubles as an agreement check on parquets that already carry the columns.
Since the miner also now splits "removed" into "removed_direct" /
"removed_transitive" (remediation.classify_removal), re-running this script
against an OLDER parquet that only has the unsplit "removed" value will
report those rows as disagreements — that's the split refining, not a bug;
disagreements on "upgraded"/"anomalous_still_present" rows are the ones that
indicate a real problem.

For every status == "found" row, the three ROOT_LOCKFILES are read at
fix_commit_sha via `remediation.lockfile_versions_at`. The search probes
guaranteed those blobs are cached for every lockfile that had commits in the
window; the remaining names are at most two raw-blob fetches per row (usually
404 -> missing, cached afterwards), off the core-API budget. A "removed"
verdict is further split by reading the root package.json at the boundary
(last-seen) and fix commits via `remediation.package_json_direct_deps_at`
(cache-first, same convention). With --cache-only, a cache miss on either the
lockfile or manifest fetch records fix_kind="unknown" (lockfile) or leaves
the unsplit "removed" (manifest) instead of fetching.

    .venv/bin/python scripts/backfill_fix_kind.py [--data-dir data]
        [--cache-only] [--dry-run] [--spot-check N]

The parquet is rewritten in place after a one-time sibling backup
(remediation_events.pre_fix_kind.parquet). Re-runs are idempotent.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from pathlib import Path

import httpx
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from js_vuln_study.lockfiles import ROOT_LOCKFILES  # noqa: E402
from js_vuln_study.remediation import (  # noqa: E402
    _cache_file, classify_fix, classify_removal, derive_units,
    lockfile_versions_at, package_json_direct_deps_at,
)
from js_vuln_study.triangulate import RAW_GITHUB, parse_owner_repo  # noqa: E402

log = logging.getLogger("backfill_fix_kind")


def _boundary_sha_map(data_dir: Path) -> dict[str, str | None]:
    """unit_key -> boundary_sha, re-derived offline from the current parquet
    tables (pure computation, no API). remediation_events rows don't persist
    boundary_sha, so this recovers it for the removal-kind split; a row whose
    unit_key isn't found here (grid/mining changed since it was mined) gets
    no split, same as an unreadable manifest."""
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet")
    vulns = pd.read_parquet(data_dir / "tables" / "vulns.parquet")
    units, _ = derive_units(vulns, analyses)
    return {u.unit_key: u.boundary_sha for u in units}


def _row_unit_key(row) -> str:
    versions = ",".join(sorted(str(row.affected_version).split(",")))
    return "|".join((row.npm_name, row.affected_dependency, versions,
                     row.last_seen, row.next_snapshot))


def _manifest_direct_deps(slug: str, sha: str | None, cache_dir: Path,
                          http_raw: httpx.Client | None) -> set[str] | None:
    """package.json direct deps at `sha`, cache-first; None if unknowable
    (missing sha, cache miss with --cache-only, or unparseable manifest)."""
    if not sha:
        return None
    path = _cache_file(cache_dir, "manifests", slug, sha, "package.json")
    if path.exists():
        payload = json.loads(path.read_text())
        deps = payload["deps"]
        return set(deps) if deps is not None else None
    if http_raw is None:
        return None
    return package_json_direct_deps_at(http_raw, cache_dir, slug, sha)


def _slug_map(data_dir: Path) -> dict[str, str]:
    """project_id -> owner/repo slug from analyses.parquet git_url."""
    analyses = pd.read_parquet(data_dir / "tables" / "analyses.parquet",
                               columns=["project_id", "git_url", "npm_name"])
    out: dict[str, str] = {}
    for r in analyses.drop_duplicates("project_id").itertuples(index=False):
        owner_repo = parse_owner_repo(str(r.git_url))
        if not owner_repo:
            raise SystemExit(f"unparseable git_url for {r.npm_name}: {r.git_url}")
        slug = "/".join(owner_repo)
        if slug != r.npm_name:
            raise SystemExit(
                f"slug mismatch for project {r.project_id}: git_url gives "
                f"{slug!r} but npm_name is {r.npm_name!r}")
        out[r.project_id] = slug
    return out


def _classify_row(row, slug: str, cache_dir: Path,
                  http_raw: httpx.Client | None,
                  boundary_sha: str | None) -> tuple[str, str | None]:
    """(fix_kind, fix_to_version) for one found row.

    Cached blobs (exactly the lockfile names the search probed at the fix
    sha) usually settle the verdict: if the dependency still resolves there,
    it is an upgrade and the never-probed names cannot flip that. Only an
    apparent removal needs the missing names checked, since the dependency
    could live in a lockfile that saw no commits in the window; those are
    raw-fetched (then cached), or reported "unknown" with --cache-only. A
    "removed" verdict is further split direct/transitive from the root
    package.json's direct-dependency set at the boundary and fix commits
    (unknown boundary_sha, or an unreadable manifest, keeps it unsplit)."""
    states: dict[str, dict[str, set[str]] | None] = {}
    missing: list[str] = []
    for name in ROOT_LOCKFILES:
        path = _cache_file(cache_dir, "blobs", slug, row.fix_commit_sha, name)
        if path.exists():
            payload = json.loads(path.read_text())
            versions = payload["versions"]
            states[name] = ({n: set(v) for n, v in versions.items()}
                            if versions is not None else None)
        else:
            missing.append(name)
    vulnerable = set(str(row.affected_version).split(","))
    kind, to_version = classify_fix(states, row.affected_dependency, vulnerable)
    if kind == "removed" and missing:
        if http_raw is None:
            return "unknown", None
        for name in missing:
            _, versions = lockfile_versions_at(http_raw, cache_dir, slug,
                                               row.fix_commit_sha, name)
            states[name] = versions
        kind, to_version = classify_fix(states, row.affected_dependency,
                                        vulnerable)
    if kind == "removed":
        deps_boundary = _manifest_direct_deps(slug, boundary_sha, cache_dir, http_raw)
        deps_fix = _manifest_direct_deps(slug, row.fix_commit_sha, cache_dir, http_raw)
        kind = classify_removal(deps_boundary, deps_fix, row.affected_dependency)
    return kind, to_version


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", default="data", type=Path)
    ap.add_argument("--cache-only", action="store_true",
                    help="never fetch; record fix_kind='unknown' on cache miss")
    ap.add_argument("--dry-run", action="store_true",
                    help="classify and report, do not rewrite the parquet")
    ap.add_argument("--spot-check", type=int, default=0, metavar="N",
                    help="print N random classified rows for manual review")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    data_dir = args.data_dir if args.data_dir.is_absolute() else ROOT / args.data_dir
    events_path = data_dir / "tables" / "remediation_events.parquet"
    if not events_path.exists():
        raise SystemExit(f"missing {events_path}")
    cache_dir = data_dir / "mining_cache"
    events = pd.read_parquet(events_path)
    slugs = _slug_map(data_dir)
    boundary_shas = _boundary_sha_map(data_dir)

    had_columns = "fix_kind" in events.columns
    prior = events["fix_kind"].copy() if had_columns else None

    http_raw = None
    if not args.cache_only:
        http_raw = httpx.Client(base_url=RAW_GITHUB, timeout=30.0,
                                follow_redirects=True)
    kinds: list[str | None] = []
    to_versions: list[str | None] = []
    try:
        for row in events.itertuples(index=False):
            if row.status != "found":
                kinds.append(None)
                to_versions.append(None)
                continue
            slug = slugs.get(row.project_id, row.npm_name)
            boundary_sha = boundary_shas.get(_row_unit_key(row))
            kind, to_version = _classify_row(row, slug, cache_dir, http_raw, boundary_sha)
            kinds.append(kind)
            to_versions.append(to_version)
    finally:
        if http_raw is not None:
            http_raw.close()

    events["fix_kind"] = kinds
    events["fix_to_version"] = to_versions

    found = events[events["status"] == "found"]
    counts = found["fix_kind"].value_counts(dropna=False).to_dict()
    log.info("found rows: %d — fix_kind counts: %s", len(found), counts)
    log.info("by method: %s", found.groupby("method")["fix_kind"]
             .value_counts().to_dict())

    # Invariants: found <=> classified; upgraded rows' surviving versions are
    # disjoint from the vulnerable set (violations were already diverted to
    # 'anomalous_still_present' by classify_fix, so any hit here is a bug).
    assert events.loc[events["status"] != "found", "fix_kind"].isna().all()
    assert found["fix_kind"].notna().all()
    for r in found[found["fix_kind"] == "upgraded"].itertuples(index=False):
        assert not (set(r.fix_to_version.split(",")) &
                    set(str(r.affected_version).split(","))), r
    anomalous = int((found["fix_kind"] == "anomalous_still_present").sum())
    unknown = int((found["fix_kind"] == "unknown").sum())
    if anomalous:
        log.warning("%d anomalous_still_present rows (vulnerable version "
                    "still resolves in a lockfile outside the search set)",
                    anomalous)
    if unknown:
        log.warning("%d rows unclassified on cache miss (--cache-only)", unknown)

    if prior is not None:
        comparable = found[prior.loc[found.index].notna()]
        disagree = comparable[
            prior.loc[comparable.index] != comparable["fix_kind"]]
        log.info("agreement check vs existing fix_kind: %d/%d disagree",
                 len(disagree), len(comparable))
        for r in disagree.head(20).itertuples(index=False):
            log.warning("disagree: %s %s @%s", r.npm_name,
                        r.affected_dependency, r.fix_commit_sha)

    if args.spot_check:
        sample = found.sample(min(args.spot_check, len(found)),
                              random_state=42)
        for r in sample.itertuples(index=False):
            to_v = r.fix_to_version if isinstance(r.fix_to_version, str) else "-"
            print(f"{r.fix_kind:26s} {r.npm_name:40s} {r.affected_dependency:32s} "
                  f"{str(r.affected_version):24s} -> {to_v:24s} "
                  f"https://github.com/{slugs.get(r.project_id, r.npm_name)}"
                  f"/commit/{r.fix_commit_sha}")

    if args.dry_run:
        log.info("dry run: parquet not rewritten")
        return 0
    backup = events_path.with_name("remediation_events.pre_fix_kind.parquet")
    if not backup.exists():
        pd.read_parquet(events_path).to_parquet(backup, index=False)
        log.info("backup written to %s", backup)
    events.to_parquet(events_path, index=False)
    log.info("rewrote %s (%d rows)", events_path, len(events))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
