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
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .client import CodeClarityClient, CodeClarityError, TERMINAL_STATUSES
from .reclaim import leaf_for, reclaim_leaf
from .sample import ProjectSpec
from .snapshots import SNAPSHOT_DATES, Snapshot, resolve_head, resolve_snapshots

log = logging.getLogger(__name__)

PLUGIN_TYPES = ["js-sbom", "vuln-finder", "license-finder"]

POLL_INITIAL = 10.0
POLL_MAX = 120.0
# Stall timeout: max time a *running* analysis may go WITHOUT any forward
# progress before we give up on it. Progress is the per-step signature
# (_progress_sig), not just the coarse top-level status, so the clock resets on
# any real movement (queued → started → ongoing → per-step transitions →
# completed). Only a genuinely wedged, actively-running analysis (no progress for
# this long) is failed. Configurable via JS_VULN_POLL_TIMEOUT (seconds).
POLL_TIMEOUT = int(os.environ.get("JS_VULN_POLL_TIMEOUT", str(20 * 60)))
# Started ceiling: how long an analysis that is *only ever queued* (top-level
# 'started'/'queued', no step has begun) may sit before we give up. A deep
# download queue legitimately holds analyses in 'started' for a long time (the
# downloader is a serial consumer — ticket 005), so the stall timeout must NOT
# apply here or queued work gets mass-failed (the 2026-06 regression). The server
# drives these to a terminal state on its own (ticket 005 fail-fast + ticket 003
# reaper retiring non-terminal work past RECOVERY_MAX_AGE, default 24h); this
# generous ceiling is just a final client-side backstop. Configurable via
# JS_VULN_STARTED_TIMEOUT (seconds); 0 disables it (poll queued work forever).
STARTED_TIMEOUT = int(os.environ.get("JS_VULN_STARTED_TIMEOUT", str(24 * 60 * 60)))

# Top-level statuses that mean the analysis is merely queued, not yet running
# (waiting for the downloader / dispatcher to pick it up).
QUEUED_STATUSES = {"started", "queued", "", None}


@dataclass
class AnalysisRecord:
    npm_name: str
    tier: str
    rank: int
    git_url: str
    branch: str | None
    # "*" is a sentinel used by project-wide 'skipped' rows (drops that happen
    # before any snapshot is known); it never collides with a real snapshot date.
    snapshot_date: str
    commit_hash: str | None
    committed_at: str | None
    # None for drops recorded before a project was imported (status='skipped').
    project_id: str | None
    analysis_id: str | None
    status: str
    error: str | None = None


def _manifest_path(data_dir: Path) -> Path:
    return data_dir / "manifest.jsonl"


def _append_record(data_dir: Path, rec: AnalysisRecord) -> None:
    _manifest_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
    with _manifest_path(data_dir).open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


def _record_skip(
    data_dir: Path,
    spec: ProjectSpec,
    snapshot_date: str,
    reason: str,
) -> AnalysisRecord:
    """Append a 'skipped' manifest row for a (project, snapshot) pair dropped
    before an analysis could be submitted, so `collect` can report true coverage.

    snapshot_date is "*" for project-wide drops (resolution/import failure, where
    no individual snapshot is known yet).
    """
    rec = AnalysisRecord(
        npm_name=spec.npm_name,
        tier=spec.tier,
        rank=spec.rank,
        git_url=spec.git_url,
        branch=None,
        snapshot_date=snapshot_date,
        commit_hash=None,
        committed_at=None,
        project_id=None,
        analysis_id=None,
        status="skipped",
        error=reason,
    )
    _append_record(data_dir, rec)
    return rec


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


def _load_project_ids(data_dir: Path) -> dict[str, str]:
    """Return {git_url: project_id} from previously recorded analyses, so re-runs
    reuse existing projects instead of importing duplicates. The manifest is a
    local, pagination-immune source of truth; server-side import is also
    idempotent, so this is purely an optimization that avoids a redundant POST."""
    path = _manifest_path(data_dir)
    if not path.exists():
        return {}
    ids: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("project_id"):
            ids[rec["git_url"]] = rec["project_id"]
    return ids


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
    project_ids = _load_project_ids(data_dir)
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
            _record_skip(data_dir, spec, "*", f"snapshot-resolution: {e}")
            continue

        if branch is None or not snapshots:
            log.info("skipping %s: no default branch / no snapshots", spec.git_url)
            _record_skip(data_dir, spec, "*", "no default branch / no snapshots")
            continue

        project_id = project_ids.get(spec.git_url)
        if project_id is None:
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
                _record_skip(data_dir, spec, "*", f"import: {e}")
                continue
            project_ids[spec.git_url] = project_id

        for snap in snapshots:
            key = (spec.git_url, snap.date)
            if key in seen:
                continue
            if snap.date == "HEAD" and snap.commit_hash is None:
                snap = _pin_head(spec, branch, snap)
            rec = _submit_analysis(client, org_id, project_id, analyzer_id, spec, branch, snap)
            _append_record(data_dir, rec)
            pending.append(rec)

    return pending


def _pin_head(spec: ProjectSpec, branch: str, snap: Snapshot) -> Snapshot:
    """Pin a HEAD snapshot to the branch tip's SHA resolved at submit time.

    snapshot_date stays "HEAD" (the manifest/collect grouping key) but the
    analysis is submitted with a concrete commit_hash, so the row is
    reproducible and the clone leaf is the commit — consistent with historical
    rows and with reclaim's leaf_for. On resolution failure the branch-only
    submission is kept: the analysis still runs, it's just unpinned.
    """
    try:
        head = resolve_head(spec.github_owner, spec.github_repo, branch)
    except Exception as e:  # noqa: BLE001 — an unpinned submit beats a lost one
        head = None
        log.warning("HEAD resolution errored for %s@%s: %s", spec.git_url, branch, e)
    if head is None:
        log.warning("could not resolve HEAD sha for %s@%s; submitting unpinned", spec.git_url, branch)
        return snap
    sha, committed_at = head
    return Snapshot(date=snap.date, commit_hash=sha, committed_at=committed_at)


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


HAPPY_TERMINAL = {"completed", "success"}
# Terminal statuses that mean the analysis did not succeed. 'cancelled' is not in
# the imported TERMINAL_STATUSES set but is a terminal sad state we must honour.
SAD_TERMINAL = (TERMINAL_STATUSES | {"cancelled"}) - HAPPY_TERMINAL
# Manifest statuses `retry` re-drives by default: every sad-terminal server
# status plus rows whose submission itself failed.
RETRYABLE_STATUSES = SAD_TERMINAL | {"failed-submit"}


def _spec_from_record(rec: dict) -> ProjectSpec:
    """Rebuild the ProjectSpec fields a re-submit needs from a manifest row.

    _submit_analysis only reads npm_name/tier/rank/git_url; owner/repo are
    re-derived from the git_url for completeness.
    """
    owner, _, repo = rec["git_url"].removeprefix("https://github.com/").partition("/")
    return ProjectSpec(
        npm_name=rec["npm_name"],
        rank=rec.get("rank") or 0,
        tier=rec.get("tier") or "",
        git_url=rec["git_url"],
        github_owner=owner,
        github_repo=repo,
        default_branch=rec.get("branch") or "",
    )


def retry_failed(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
    data_dir: Path,
    statuses: set[str] | None = None,
    date: str | None = None,
    project: str | None = None,
    dry_run: bool = False,
) -> list[AnalysisRecord]:
    """Re-submit sad-terminal manifest rows and replace them in place.

    Each selected row is rebuilt into a Snapshot from its stored
    snapshot_date/commit_hash/committed_at (a pinned HEAD stays pinned to the
    same commit) and re-driven through _submit_analysis. The row is replaced —
    fresh analysis_id, status 'submitted', error cleared — never appended, so
    the (git_url, snapshot_date) dedupe key stays unique. Returns the
    re-submitted records.
    """
    path = _manifest_path(data_dir)
    if not path.exists():
        log.warning("no manifest at %s", path)
        return []
    statuses = set(statuses) if statuses else set(RETRYABLE_STATUSES)

    records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    selected = [
        i for i, r in enumerate(records)
        if r.get("status") in statuses
        and (date is None or r.get("snapshot_date") == date)
        and (project is None or r.get("npm_name") == project)
    ]
    log.info("retry: %d of %d manifest rows match statuses=%s", len(selected), len(records), sorted(statuses))

    resubmitted: list[AnalysisRecord] = []
    for i in selected:
        rec = records[i]
        if not rec.get("project_id") or not rec.get("branch"):
            # 'skipped'-style rows never got a project/branch; retry can't
            # rebuild a submission from them — re-run `submit` instead.
            log.warning(
                "cannot retry %s@%s (status=%s): no project_id/branch recorded",
                rec.get("npm_name"), rec.get("snapshot_date"), rec.get("status"),
            )
            continue
        if dry_run:
            log.info(
                "[dry-run] would resubmit %s@%s (%s, was %s)",
                rec["npm_name"], rec["snapshot_date"],
                rec.get("commit_hash") or rec["branch"], rec["status"],
            )
            continue
        snap = Snapshot(
            date=rec["snapshot_date"],
            commit_hash=rec.get("commit_hash"),
            committed_at=rec.get("committed_at"),
        )
        new_rec = _submit_analysis(
            client, org_id, rec["project_id"], analyzer_id,
            _spec_from_record(rec), rec["branch"], snap,
        )
        records[i] = asdict(new_rec)
        resubmitted.append(new_rec)
        # Flush after every replacement so Ctrl-C never double-submits a row.
        _rewrite_manifest(path, records)

    if not dry_run:
        log.info("retry: resubmitted %d row(s)", len(resubmitted))
    return resubmitted


def _progress_sig(analysis: dict) -> tuple:
    """A fine-grained progress signature: top-level status plus every step's
    (name, status). It changes on any real forward movement — a step starting,
    a stage advancing — not just the coarse top-level status flip, so the stall
    clock resets on genuine progress rather than only on queued→ongoing."""
    steps = analysis.get("steps") or []
    step_states = tuple(
        (s.get("name"), s.get("status"))
        for stage in (steps or [])
        for s in (stage or [])
    )
    return (analysis.get("status"), step_states)


def _is_running(analysis: dict) -> bool:
    """True once the analysis is actually being processed (not merely queued):
    the top-level status is past 'started'/'queued', or some step has begun.

    NB: a *step* status of 'started' means that step is executing (the dispatcher
    stamps STARTED on dispatch) — that counts as running. An un-dispatched step
    has an empty/None status."""
    if analysis.get("status") not in QUEUED_STATUSES:
        return True
    for stage in (analysis.get("steps") or []):
        for s in (stage or []):
            if s.get("status"):  # any non-empty step status => dispatched/begun
                return True
    return False


def _failure_reason(
    client: CodeClarityClient,
    org_id: str,
    rec: dict,
    analysis: dict,
) -> str:
    """Build a concrete reason for a sad-terminal analysis. Prefer the API's
    analysis-level failure_reason (written by the downloader on unresolvable
    commits / download errors); older analyses predate the column, so fall back
    to reading the failing step names from `steps` and pulling the plugin error
    out of the result blob (analysis_info.errors[].public_error.{key,description})."""
    reason = (analysis.get("failure_reason") or "").strip()
    if reason:
        return reason
    failed_steps = [
        s.get("name")
        for stage in (analysis.get("steps") or [])
        for s in (stage or [])
        if s.get("status") in SAD_TERMINAL and s.get("name")
    ]
    for plugin in (failed_steps or PLUGIN_TYPES):
        try:
            blob = client.get_result(org_id, rec["project_id"], rec["analysis_id"], plugin)
        except CodeClarityError:
            continue
        errors = (((blob or {}).get("analysis_info") or {}).get("errors")) or []
        for err in errors:
            pub = (err or {}).get("public_error") or {}
            key = pub.get("key") or "Error"
            desc = pub.get("description") or ""
            return f"{plugin}: {key}: {desc}".strip().rstrip(":").strip()
    where = ", ".join(failed_steps) if failed_steps else "stage-0/download"
    return f"failure at {where}; no plugin result"


def _leaf_key(rec: dict) -> tuple[str, str] | None:
    """The (project_id, clone-directory-leaf) a manifest record maps to.

    reclaim.py deliberately doesn't know the manifest schema, so the adapter
    lives here. Mirrors client.start_analysis's project_path construction.
    """
    project_id = rec.get("project_id")
    leaf = leaf_for(rec.get("commit_hash"), rec.get("branch"))
    return (project_id, leaf) if project_id and leaf else None


def _active_leaves(records: list[dict]) -> Counter:
    """How many still-in-flight records map to each clone leaf.

    Two records can share a leaf (two HEAD analyses on `main`, or a
    re-submission), so a leaf may only be reclaimed once the last of them is
    terminal. Counted over *all* records, not just the ones this process is
    polling, because a concurrent `run.py submit` can append rows.
    """
    return Counter(
        key
        for r in records
        if r.get("status") == "submitted" and (key := _leaf_key(r)) is not None
    )


def poll_and_collect(
    client: CodeClarityClient,
    org_id: str,
    data_dir: Path,
) -> None:
    """Scan the manifest, poll every submitted analysis until terminal, and
    persist its plugin results under `data/raw/`.

    Once results are safely persisted, the analysis's downloader clone is
    deleted (see reclaim.py) — otherwise a longitudinal run accumulates one
    ~10 MB checkout per snapshot until the disk fills. Set
    JS_VULN_CLONE_DIR=/nonexistent to disable that if you need to inspect the
    checkouts of failed analyses by hand.

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

    now = time.time()
    # last_progress: wall-clock of the most recent observed forward progress.
    # last_sig: the progress signature at that time (see _progress_sig).
    # first_seen: when we started polling this analysis (the started-ceiling base).
    last_progress: dict[int, float] = {i: now for i in active_idx}
    last_sig: dict[int, tuple] = {i: () for i in active_idx}
    first_seen: dict[int, float] = {i: now for i in active_idx}
    wait = POLL_INITIAL
    last_summary = time.time()
    reclaimed_bytes = 0

    while active_idx:
        still_active: list[int] = []
        iter_statuses: dict[str, int] = {}
        queued_count = 0
        # Rebuilt each pass so rows appended by a concurrent `submit` are seen.
        active_leaves = _active_leaves(records)
        for i in active_idx:
            rec = records[i]
            try:
                analysis = client.get_analysis(org_id, rec["project_id"], rec["analysis_id"])
            except CodeClarityError as e:
                log.warning("get_analysis failed for %s: %s", rec["analysis_id"], e)
                # A transient poll error is not progress, but it is also not a
                # stall of the analysis itself — keep waiting unless the run has
                # already overrun the started ceiling.
                if STARTED_TIMEOUT and time.time() - first_seen[i] > STARTED_TIMEOUT:
                    rec["status"] = "failed"
                    rec["error"] = f"poll error past started ceiling: {e}"
                    _rewrite_manifest(path, records)
                else:
                    still_active.append(i)
                continue

            status = analysis.get("status")
            iter_statuses[status or "?"] = iter_statuses.get(status or "?", 0) + 1
            running = _is_running(analysis)
            if not running:
                queued_count += 1

            # Reset the stall clock on any real forward progress (per-step, not
            # just the coarse top-level status), so work waiting behind a deep
            # queue or limited plugin workers is never failed for being slow.
            sig = _progress_sig(analysis)
            if sig != last_sig.get(i):
                last_sig[i] = sig
                last_progress[i] = time.time()

            terminated = False
            if status in TERMINAL_STATUSES or status == "cancelled":
                rec["status"] = status
                if status in HAPPY_TERMINAL:
                    _persist_results(client, org_id, rec, data_dir)
                else:
                    rec["error"] = _failure_reason(client, org_id, rec, analysis)
                    _persist_results(client, org_id, rec, data_dir)
                    log.info(
                        "analysis %s terminated status=%s: %s",
                        rec["analysis_id"], status, rec["error"],
                    )
                # Results are persisted (and _failure_reason has already read
                # the plugin blobs over the API), so the checkout is dead weight.
                # Sad-terminal clones are reclaimed too: they are often partial
                # trees, failures cluster in longitudinal runs, and a re-submitted
                # analysis re-clones anyway.
                reclaimed_bytes += _reclaim_for_record(org_id, rec, active_leaves)
                terminated = True
            elif running and time.time() - last_progress[i] > POLL_TIMEOUT:
                # Actively running but wedged — no forward progress for the stall
                # window. This is a genuine failure, not mere queueing.
                stalled = int(time.time() - last_progress[i])
                rec["status"] = "failed"
                rec["error"] = f"ongoing stall: no progress for {stalled}s"
                terminated = True
            elif STARTED_TIMEOUT and time.time() - first_seen[i] > STARTED_TIMEOUT:
                # Only ever queued, but past the generous started ceiling — the
                # server backstops should have made it terminal by now.
                rec["status"] = "failed"
                rec["error"] = "queued > started ceiling"
                terminated = True
            # NB: neither client-side timeout branch reclaims the clone. Those
            # give up locally while the *server-side* analysis may still be
            # running and writing into the checkout; `clean --clones` collects
            # them later, once nothing is in flight.
            else:
                still_active.append(i)
            # Flush manifest after every transition so Ctrl-C never loses progress.
            if terminated:
                _rewrite_manifest(path, records)

        active_idx = still_active
        if active_idx:
            # Summarise non-terminal state every ~30s so wedged backends are visible.
            if time.time() - last_summary > 30:
                log.info(
                    "waiting on %d analyses (%d still queued, position unknown); statuses=%s",
                    len(active_idx), queued_count, iter_statuses,
                )
                last_summary = time.time()
            jitter = random.uniform(0.8, 1.2)
            time.sleep(min(POLL_MAX, wait) * jitter)
            wait = min(POLL_MAX, wait * 1.5)

    _rewrite_manifest(path, records)
    if reclaimed_bytes:
        log.info("poll complete; reclaimed %.1f MB of clones", reclaimed_bytes / 1e6)


def _reclaim_for_record(org_id: str, rec: dict, active_leaves: Counter) -> int:
    """Delete the clone backing a now-terminal record. Returns bytes freed.

    `active_leaves` counts records still in flight per leaf; this record's own
    entry is decremented first, and the directory is only removed once nothing
    else is using it.
    """
    key = _leaf_key(rec)
    if key is None:
        return 0
    if active_leaves.get(key, 0) > 0:
        active_leaves[key] -= 1
    if active_leaves.get(key, 0) > 0:
        log.debug("skip reclaim of %s/%s: leaf still in use", *key)
        return 0

    project_id, leaf = key
    freed = reclaim_leaf(org_id, project_id, leaf)
    if freed:
        log.info("reclaimed %.1f MB from %s/%s", freed / 1e6, project_id, leaf)
    return freed


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
