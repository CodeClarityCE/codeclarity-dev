"""Drives the full scan pipeline for the JS vulnerability-evolution study.

Workflow per project:
  1. Resolve commit hashes at each target date (GitHub API).
  2. Import the project into CodeClarity (once per project).
  3. For each snapshot, POST an analysis and record the analysis_id.
  4. Poll analyses concurrently with exponential backoff until terminal.
  5. Persist the four plugin result blobs (js-sbom, vuln-finder, license-finder,
     js-patching) to `data/raw/{project_id}/{analysis_id}/{plugin}.json`.

A run manifest (`data/manifest.jsonl`) records every (project, snapshot, analysis)
tuple with its status so the collector can produce a tidy DataFrame.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .client import CodeClarityClient, CodeClarityError, TERMINAL_STATUSES
from .sample import ProjectSpec
from .snapshots import SNAPSHOT_DATES, Snapshot, resolve_snapshots

log = logging.getLogger(__name__)

PLUGIN_TYPES = ["js-sbom", "vuln-finder", "license-finder"]

POLL_INITIAL = 10.0
POLL_MAX = 120.0
# Stall timeout: max time an analysis may go WITHOUT any server-side status
# change before we give up on it. The clock resets on every observed transition
# (queued → started → ongoing → completed), so a large batch that waits its turn
# behind limited plugin workers is never killed for being slow — only a
# genuinely wedged analysis (no progress for this long) is failed.
# Configurable via JS_VULN_POLL_TIMEOUT (seconds) — raise it for deep queues
# (e.g. the ~1,700-analysis longitudinal run) where items wait long in 'started'.
POLL_TIMEOUT = int(os.environ.get("JS_VULN_POLL_TIMEOUT", str(20 * 60)))


@dataclass
class AnalysisRecord:
    npm_name: str
    tier: str
    rank: int
    git_url: str
    branch: str | None
    snapshot_date: str
    commit_hash: str | None
    committed_at: str | None
    project_id: str
    analysis_id: str | None
    status: str
    error: str | None = None


def _manifest_path(data_dir: Path) -> Path:
    return data_dir / "manifest.jsonl"


def _append_record(data_dir: Path, rec: AnalysisRecord) -> None:
    _manifest_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
    with _manifest_path(data_dir).open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


def _load_existing_manifest(data_dir: Path) -> set[tuple[str, str]]:
    """Return the set of (git_url, snapshot_date) pairs we've already recorded,
    so resuming a run doesn't re-submit analyses that are already tracked."""
    path = _manifest_path(data_dir)
    if not path.exists():
        return set()
    seen: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        seen.add((rec["git_url"], rec["snapshot_date"]))
    return seen


def import_and_schedule(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
    projects: Iterable[ProjectSpec],
    data_dir: Path,
    integration_id: str | None = None,
    skip_head_only: bool = False,
) -> list[AnalysisRecord]:
    """Import each project and kick off one analysis per snapshot.

    Returns the list of in-flight analysis records (status='submitted' or 'failed-submit').
    """
    seen = _load_existing_manifest(data_dir)
    pending: list[AnalysisRecord] = []

    for spec in projects:
        try:
            # HEAD-only is the default: pass an empty date grid so we skip the
            # per-repo historical commit lookups entirely and only resolve HEAD.
            branch, snapshots = resolve_snapshots(
                spec.github_owner,
                spec.github_repo,
                dates=[] if skip_head_only else SNAPSHOT_DATES,
                include_head=True,
            )
        except Exception as e:  # noqa: BLE001 — we want to log and continue per project
            log.warning("snapshot resolution failed for %s: %s", spec.git_url, e)
            continue

        if branch is None or not snapshots:
            log.info("skipping %s: no default branch / no snapshots", spec.git_url)
            continue

        try:
            project_id = client.import_project(
                org_id,
                spec.git_url,
                name=spec.npm_name,
                description=f"{spec.tier} rank={spec.rank}",
                integration_id=integration_id,
            )
        except CodeClarityError as e:
            log.warning("import failed for %s: %s", spec.git_url, e)
            continue

        for snap in snapshots:
            key = (spec.git_url, snap.date)
            if key in seen:
                continue
            rec = _submit_analysis(client, org_id, project_id, analyzer_id, spec, branch, snap)
            _append_record(data_dir, rec)
            pending.append(rec)

    return pending


def _submit_analysis(
    client: CodeClarityClient,
    org_id: str,
    project_id: str,
    analyzer_id: str,
    spec: ProjectSpec,
    branch: str,
    snap: Snapshot,
) -> AnalysisRecord:
    try:
        analysis_id = client.start_analysis(
            org_id=org_id,
            project_id=project_id,
            analyzer_id=analyzer_id,
            branch=branch,
            commit_hash=snap.commit_hash,
        )
        status = "submitted"
        err = None
    except CodeClarityError as e:
        analysis_id = None
        status = "failed-submit"
        err = str(e)
        log.warning("start_analysis failed for %s@%s: %s", spec.npm_name, snap.date, e)
    return AnalysisRecord(
        npm_name=spec.npm_name,
        tier=spec.tier,
        rank=spec.rank,
        git_url=spec.git_url,
        branch=branch,
        snapshot_date=snap.date,
        commit_hash=snap.commit_hash,
        committed_at=snap.committed_at,
        project_id=project_id,
        analysis_id=analysis_id,
        status=status,
        error=err,
    )


def poll_and_collect(
    client: CodeClarityClient,
    org_id: str,
    data_dir: Path,
) -> None:
    """Scan the manifest, poll every submitted analysis until terminal, and
    persist its plugin results under `data/raw/`.

    The manifest is rewritten atomically at the end with updated statuses.
    """
    path = _manifest_path(data_dir)
    if not path.exists():
        log.warning("no manifest at %s", path)
        return

    records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    active_idx = [
        i for i, r in enumerate(records)
        if r.get("status") == "submitted" and r.get("analysis_id")
    ]
    log.info("polling %d active analyses", len(active_idx))

    deadlines: dict[int, float] = {i: time.time() + POLL_TIMEOUT for i in active_idx}
    last_status: dict[int, str | None] = {i: None for i in active_idx}
    wait = POLL_INITIAL
    last_summary = time.time()

    while active_idx:
        still_active: list[int] = []
        iter_statuses: dict[str, int] = {}
        for i in active_idx:
            rec = records[i]
            try:
                analysis = client.get_analysis(org_id, rec["project_id"], rec["analysis_id"])
            except CodeClarityError as e:
                log.warning("get_analysis failed for %s: %s", rec["analysis_id"], e)
                if time.time() > deadlines[i]:
                    rec["status"] = "failed"
                    rec["error"] = f"poll error: {e}"
                else:
                    still_active.append(i)
                continue

            status = analysis.get("status")
            iter_statuses[status or "?"] = iter_statuses.get(status or "?", 0) + 1
            # Reset the stall clock on any observed progress so queued analyses
            # aren't failed while merely waiting behind limited plugin workers.
            if status != last_status.get(i):
                last_status[i] = status
                deadlines[i] = time.time() + POLL_TIMEOUT
            terminated = False
            if status in TERMINAL_STATUSES:
                rec["status"] = status
                if status in {"completed", "success"}:
                    _persist_results(client, org_id, rec, data_dir)
                else:
                    log.info("analysis %s terminated with status=%s", rec["analysis_id"], status)
                terminated = True
            elif time.time() > deadlines[i]:
                rec["status"] = "failed"
                rec["error"] = "poll timeout"
                terminated = True
            else:
                still_active.append(i)
            # Flush manifest after every transition so Ctrl-C never loses progress.
            if terminated:
                _rewrite_manifest(path, records)

        active_idx = still_active
        if active_idx:
            # Summarise non-terminal state every ~30s so wedged backends are visible.
            if time.time() - last_summary > 30:
                log.info("waiting on %d analyses; statuses=%s", len(active_idx), iter_statuses)
                last_summary = time.time()
            jitter = random.uniform(0.8, 1.2)
            time.sleep(min(POLL_MAX, wait) * jitter)
            wait = min(POLL_MAX, wait * 1.5)

    _rewrite_manifest(path, records)


def _persist_results(
    client: CodeClarityClient,
    org_id: str,
    rec: dict,
    data_dir: Path,
) -> None:
    out_dir = data_dir / "raw" / rec["project_id"] / rec["analysis_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    for plugin in PLUGIN_TYPES:
        try:
            blob = client.get_result(org_id, rec["project_id"], rec["analysis_id"], plugin)
        except CodeClarityError as e:
            log.info("no %s result for %s (%s)", plugin, rec["analysis_id"], e)
            continue
        (out_dir / f"{plugin}.json").write_text(json.dumps(blob), encoding="utf-8")


def _rewrite_manifest(path: Path, records: list[dict]) -> None:
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    tmp.replace(path)
