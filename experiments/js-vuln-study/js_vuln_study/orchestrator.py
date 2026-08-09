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
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

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

# Project-level submit parallelism: one worker resolves all snapshot dates for
# one project (GitHub API calls) and submits its analyses. Manifest writes stay
# on the main thread — the workers only build records.
SUBMIT_WORKERS = int(os.environ.get("JS_VULN_SUBMIT_WORKERS", "8"))


def _utcnow_iso() -> str:
    # datetime, not the time module: poll tests replace orchestrator.time with a
    # fake clock that only implements time()/sleep().
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    # ISO-UTC telemetry stamps: when the analysis was submitted and when the
    # poll loop saw it go terminal. Older manifests predate both fields, so
    # every reader must .get them.
    submitted_at: str | None = None
    terminal_at: str | None = None
    # YYYY-MM-DD knowledge cutoff the analysis was submitted under (the
    # vuln-finder `knowledge_asof` runtime filter — a ladder rung's dose).
    # None means no cutoff was requested. Older manifests predate the field,
    # so — like the telemetry stamps — every reader must .get it.
    knowledge_asof: str | None = None


def _manifest_path(data_dir: Path) -> Path:
    return data_dir / "manifest.jsonl"


def _append_record(data_dir: Path, rec: AnalysisRecord) -> None:
    _manifest_path(data_dir).parent.mkdir(parents=True, exist_ok=True)
    with _manifest_path(data_dir).open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


def _skip_record(spec: ProjectSpec, snapshot_date: str, reason: str) -> AnalysisRecord:
    """Build (without writing) a 'skipped' manifest row for a (project, snapshot)
    pair dropped before an analysis could be submitted, so `collect` can report
    true coverage. Kept append-free so submit workers can build skip rows while
    the main thread stays the manifest's single writer.

    snapshot_date is "*" for project-wide drops (resolution/import failure, where
    no individual snapshot is known yet).
    """
    return AnalysisRecord(
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


def _record_skip(
    data_dir: Path,
    spec: ProjectSpec,
    snapshot_date: str,
    reason: str,
) -> AnalysisRecord:
    """Build and append a 'skipped' manifest row (see _skip_record)."""
    rec = _skip_record(spec, snapshot_date, reason)
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


# ---- unresolvable-commit denylist ------------------------------------------

DENYLIST_FILENAME = "unresolvable_commits.jsonl"

# Manifest `error` fragments that mark a (git_url, snapshot_date) as permanently
# unresolvable — re-driving it re-fails identically, so it's denylisted instead:
#   * "CommitUnresolvable" — the downloader's failure_reason for a historical
#     commit that no longer exists in the remote (git.go ErrCommitUnresolvable);
#     the whole wrapped error is "CommitUnresolvable: commit <sha> in <url>: …".
#   * "failure at stage-0/download; no plugin result" — _failure_reason's
#     fallback for a download-stage failure with no failure_reason recorded.
#     Empirically the stable signature of the unresolvable-commit set: the same
#     225 (git_url, snapshot_date) pairs carry exactly this error in both
#     data/manifest.jsonl and data/archive-run-2026-06-snapshot/manifest.jsonl.
# "context deadline exceeded" (download timeout) is deliberately NOT matched —
# a timeout can succeed on retry.
UNRESOLVABLE_REASON_MARKERS = (
    "CommitUnresolvable",
    "failure at stage-0/download; no plugin result",
)


def _denylist_path(data_dir: Path) -> Path:
    return data_dir / DENYLIST_FILENAME


def is_unresolvable_reason(error: str | None) -> bool:
    """True when a manifest error marks the commit as permanently unresolvable."""
    return bool(error) and any(m in error for m in UNRESOLVABLE_REASON_MARKERS)


def load_denylist(data_dir: Path) -> dict[tuple[str, str], dict]:
    """Return {(git_url, snapshot_date): row} from the denylist file."""
    path = _denylist_path(data_dir)
    if not path.exists():
        return {}
    out: dict[tuple[str, str], dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        out[(row["git_url"], row["snapshot_date"])] = row
    return out


def record_unresolvable(data_dir: Path, rec: dict, reason: str | None) -> dict:
    """Append one denylist row and return it. Callers dedup via load_denylist —
    this only appends, so the file stays a plain audit log."""
    row = {
        "git_url": rec.get("git_url"),
        "snapshot_date": rec.get("snapshot_date"),
        "commit": rec.get("commit_hash"),
        "reason": reason,
        "recorded_at": _utcnow_iso(),
    }
    path = _denylist_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    log.info(
        "denylisted %s@%s (%s): %s",
        row["git_url"], row["snapshot_date"], row["commit"], reason,
    )
    return row


def _ensure_project_id(
    client: CodeClarityClient,
    org_id: str,
    spec: ProjectSpec,
    project_ids: dict[str, str],
    ids_lock: threading.Lock,
    integration_id: str | None,
) -> str:
    """Return the project_id for spec.git_url, importing the project once if
    unknown. `project_ids` is the shared {git_url: project_id} cache (guarded
    by ids_lock); server-side import is idempotent, so a lost race costs one
    redundant POST at worst. Raises CodeClarityError when the import fails."""
    with ids_lock:
        project_id = project_ids.get(spec.git_url)
    if project_id is None:
        project_id = client.import_project(
            org_id,
            spec.git_url,
            name=spec.npm_name,
            description=f"{spec.tier} rank={spec.rank}",
            integration_id=integration_id,
        )
        with ids_lock:
            project_ids[spec.git_url] = project_id
    return project_id


def import_and_schedule(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
    projects: Iterable[ProjectSpec],
    data_dir: Path,
    integration_id: str | None = None,
    skip_head_only: bool = False,
    ignore_denylist: bool = False,
    max_workers: int = SUBMIT_WORKERS,
) -> list[AnalysisRecord]:
    """Import each project and kick off one analysis per snapshot.

    Projects are processed on a thread pool (snapshot resolution is GitHub-API
    bound and dominated the old serial submit); the manifest stays single-writer
    — workers only build records, the main thread appends them in project order,
    so the output is byte-identical to a serial run.

    Returns the list of in-flight analysis records (status='submitted' or 'failed-submit').
    """
    seen = _load_existing_manifest(data_dir)
    denylist = {} if ignore_denylist else load_denylist(data_dir)
    project_ids = _load_project_ids(data_dir)
    ids_lock = threading.Lock()

    def _process(spec: ProjectSpec) -> list[AnalysisRecord]:
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
            return [_skip_record(spec, "*", f"snapshot-resolution: {e}")]

        if branch is None or not snapshots:
            log.info("skipping %s: no default branch / no snapshots", spec.git_url)
            return [_skip_record(spec, "*", "no default branch / no snapshots")]

        try:
            project_id = _ensure_project_id(
                client, org_id, spec, project_ids, ids_lock, integration_id,
            )
        except CodeClarityError as e:
            log.warning("import failed for %s: %s", spec.git_url, e)
            return [_skip_record(spec, "*", f"import: {e}")]

        out: list[AnalysisRecord] = []
        for snap in snapshots:
            key = (spec.git_url, snap.date)
            if key in seen:
                continue
            if key in denylist:
                log.info(
                    "skipping denylisted %s@%s: %s",
                    spec.git_url, snap.date, denylist[key].get("reason"),
                )
                out.append(_skip_record(spec, snap.date, f"denylist: {denylist[key].get('reason')}"))
                continue
            if snap.date == "HEAD" and snap.commit_hash is None:
                snap = _pin_head(spec, branch, snap)
            out.append(_submit_analysis(client, org_id, project_id, analyzer_id, spec, branch, snap))
        return out

    pending: list[AnalysisRecord] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_process, spec) for spec in projects]
        # Iterate in submission (not completion) order: manifest rows land
        # grouped per project, in the sample's order — deterministic output.
        for future in futures:
            for rec in future.result():
                _append_record(data_dir, rec)
                if rec.status != "skipped":
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
    knowledge_asof: str | None = None,
) -> AnalysisRecord:
    # knowledge_asof rides in the per-analysis plugin config (merged over the
    # client's defaults) rather than a dedicated endpoint: vuln-finder reads it
    # at match time to filter the knowledge DB to rows known by that date. Only
    # sent when set, so the no-cutoff request body stays byte-identical.
    config = (
        {"vuln-finder": {"knowledge_asof": knowledge_asof}} if knowledge_asof else None
    )
    try:
        analysis_id = client.start_analysis(
            org_id=org_id,
            project_id=project_id,
            analyzer_id=analyzer_id,
            branch=branch,
            commit_hash=snap.commit_hash,
            config=config,
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
        submitted_at=_utcnow_iso(),
        knowledge_asof=knowledge_asof,
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
    re-derived from the git_url's path (host-agnostic) for completeness.
    """
    slug = urlparse(rec["git_url"]).path.strip("/")
    owner, _, repo = slug.removesuffix(".git").partition("/")
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
    ignore_denylist: bool = False,
) -> list[AnalysisRecord]:
    """Re-submit sad-terminal manifest rows and replace them in place.

    Each selected row is rebuilt into a Snapshot from its stored
    snapshot_date/commit_hash/committed_at (a pinned HEAD stays pinned to the
    same commit) and re-driven through _submit_analysis. The row is replaced —
    fresh analysis_id, status 'submitted', error cleared — never appended, so
    the (git_url, snapshot_date) dedupe key stays unique. Returns the
    re-submitted records.

    Rows on the unresolvable-commit denylist — or whose current error already
    carries an unresolvable-commit signature (recorded to the denylist on the
    spot) — are not re-driven: the row is converted in place to a 'skipped'
    record, keeping the (git_url, snapshot_date) key unique and moving it out
    of the retryable set. --ignore-denylist disables both.
    """
    path = _manifest_path(data_dir)
    if not path.exists():
        log.warning("no manifest at %s", path)
        return []
    statuses = set(statuses) if statuses else set(RETRYABLE_STATUSES)
    denylist = {} if ignore_denylist else load_denylist(data_dir)

    records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    selected = [
        i for i, r in enumerate(records)
        if r.get("status") in statuses
        and (date is None or r.get("snapshot_date") == date)
        and (project is None or r.get("npm_name") == project)
    ]
    log.info("retry: %d of %d manifest rows match statuses=%s", len(selected), len(records), sorted(statuses))

    resubmitted: list[AnalysisRecord] = []
    denylist_skipped = 0
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
        if not ignore_denylist:
            key = (rec.get("git_url"), rec.get("snapshot_date"))
            deny = denylist.get(key)
            if deny is None and is_unresolvable_reason(rec.get("error")):
                if dry_run:
                    deny = {"reason": rec.get("error")}  # don't write in dry-run
                else:
                    deny = record_unresolvable(data_dir, rec, rec.get("error"))
                    denylist[key] = deny
            if deny is not None:
                denylist_skipped += 1
                if dry_run:
                    log.info(
                        "[dry-run] would skip denylisted %s@%s: %s",
                        rec["npm_name"], rec["snapshot_date"], deny.get("reason"),
                    )
                    continue
                rec["status"] = "skipped"
                rec["error"] = f"denylist: {deny.get('reason')}"
                _rewrite_manifest(path, records)
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
        # Carry the row's knowledge cutoff into the re-submission: a rung's
        # auto-retry (poll_with_retries) must not silently re-drive an analysis
        # WITHOUT the cutoff its rung was scanned under. Older rows lack the
        # field, so .get keeps them retryable.
        new_rec = _submit_analysis(
            client, org_id, rec["project_id"], analyzer_id,
            _spec_from_record(rec), rec["branch"], snap,
            knowledge_asof=rec.get("knowledge_asof"),
        )
        records[i] = asdict(new_rec)
        resubmitted.append(new_rec)
        # Flush after every replacement so Ctrl-C never double-submits a row.
        _rewrite_manifest(path, records)

    if not dry_run:
        log.info(
            "retry: resubmitted %d row(s), denylist-skipped %d",
            len(resubmitted), denylist_skipped,
        )
    return resubmitted


def resubmit_frozen(
    client: CodeClarityClient | None,
    org_id: str,
    analyzer_id: str,
    source_manifest: Path,
    data_dir: Path,
    integration_id: str | None = None,
    only_completed: bool = False,
    dedupe_sha: bool = False,
    dry_run: bool = False,
    ignore_denylist: bool = False,
    max_workers: int = SUBMIT_WORKERS,
    knowledge_asof: str | None = None,
) -> list[AnalysisRecord]:
    """Re-submit a source manifest's rows commit-pinned at their archived SHAs.

    The ladder experiment's submit path: the SOURCE manifest (read READ-ONLY,
    never touched) fixes WHAT to scan — every selected row is re-submitted at
    its recorded commit_hash with snapshot_date carried over verbatim (pinned
    HEAD rows included: they submit at the archived SHA, never re-resolved) —
    while the knowledge-DB state behind this rung's data_dir fixes what it is
    scanned AGAINST. `knowledge_asof` (YYYY-MM-DD) is the runtime alternative
    to a restored dated dump: it is passed through to vuln-finder's per-analysis
    config so the plugin itself filters the (current) knowledge DB to that
    date, and recorded on every submitted rung-manifest row so downstream
    tooling can identify the rung without trusting the DB stamp. No GitHub
    resolution happens at all, so a submit worker is just one project's
    import-check + analysis POSTs.

    Selection: every source row, or happy-terminal rows only with
    only_completed; dedupe_sha collapses rows sharing (git_url, commit_hash)
    onto the first, so the same frozen tree is scanned once even when several
    snapshot_dates pinned to it. Rows without a commit_hash cannot be frozen
    and become 'skipped' rung-manifest rows (reason 'no pinned commit in
    source'). The RUNG manifest's own (git_url, snapshot_date) dedupe applies,
    so re-runs are resumable/idempotent per rung; the rung dir's denylist —
    merged with the source dir's, if one exists — is honoured unless
    ignore_denylist. Projects the server no longer has (archived project_ids
    are stale after `run.py clean`) are re-imported by git_url.

    dry_run prints the selection/dedup/skip summary and writes NOTHING
    (`client` may be None then). Returns the in-flight records, like
    import_and_schedule.
    """
    if not source_manifest.exists():
        log.warning("no source manifest at %s", source_manifest)
        return []
    source_rows = [
        json.loads(l)
        for l in source_manifest.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    selected = [
        r for r in source_rows
        if not only_completed or r.get("status") in HAPPY_TERMINAL
    ]
    n_selected = len(selected)
    if dedupe_sha:
        # Keep the first row per (git_url, commit_hash); sha-less rows can't
        # alias a tree, so they pass through to the skip path individually.
        deduped: list[dict] = []
        seen_sha: set[tuple[str, str]] = set()
        for r in selected:
            sha = r.get("commit_hash")
            if sha:
                key = (r.get("git_url"), sha)
                if key in seen_sha:
                    continue
                seen_sha.add(key)
            deduped.append(r)
        selected = deduped

    seen = _load_existing_manifest(data_dir)
    denylist = {} if ignore_denylist else {
        **load_denylist(source_manifest.parent),
        **load_denylist(data_dir),
    }

    # Disposition pass — pure bookkeeping, no client: what each selected row
    # will become in the rung manifest.
    dispositions: list[tuple[str, dict]] = []
    for r in selected:
        key = (r.get("git_url"), r.get("snapshot_date"))
        if key in seen:
            disposition = "already"
        elif not r.get("commit_hash"):
            disposition = "no-sha"
        elif key in denylist:
            disposition = "denylist"
        else:
            disposition = "submit"
        dispositions.append((disposition, r))
    counts = Counter(d for d, _ in dispositions)

    log.info(
        "%sresubmit-frozen from %s: %d source row(s) -> %d selected%s -> "
        "%d after sha-dedupe; %d already in rung manifest, %d missing "
        "commit_hash, %d denylisted, %d to submit",
        "[dry-run] " if dry_run else "", source_manifest, len(source_rows),
        n_selected, " (completed/success only)" if only_completed else "",
        len(selected), counts.get("already", 0), counts.get("no-sha", 0),
        counts.get("denylist", 0), counts.get("submit", 0),
    )
    if dry_run:
        return []

    try:
        project_ids = {
            p["url"]: p["id"] for p in client.list_projects(org_id) if p.get("url")
        }
    except CodeClarityError as e:
        log.warning(
            "could not list projects (%s); falling back to the rung manifest's ids", e,
        )
        project_ids = _load_project_ids(data_dir)
    ids_lock = threading.Lock()

    work: dict[str, list[tuple[str, dict]]] = {}
    for disposition, r in dispositions:
        if disposition != "already":
            work.setdefault(r["git_url"], []).append((disposition, r))

    def _process(items: list[tuple[str, dict]]) -> list[AnalysisRecord]:
        out: list[AnalysisRecord] = []
        project_id: str | None = None
        import_failed = False
        for disposition, rec in items:
            spec = _spec_from_record(rec)
            if disposition == "no-sha":
                out.append(_skip_record(
                    spec, rec.get("snapshot_date") or "*",
                    "no pinned commit in source",
                ))
                continue
            if disposition == "denylist":
                deny = denylist[(rec["git_url"], rec["snapshot_date"])]
                log.info(
                    "skipping denylisted %s@%s: %s",
                    rec["git_url"], rec["snapshot_date"], deny.get("reason"),
                )
                out.append(_skip_record(
                    spec, rec["snapshot_date"], f"denylist: {deny.get('reason')}",
                ))
                continue
            if import_failed:
                continue  # the project-wide "*" skip row already covers this
            if project_id is None:
                try:
                    project_id = _ensure_project_id(
                        client, org_id, spec, project_ids, ids_lock, integration_id,
                    )
                except CodeClarityError as e:
                    log.warning("import failed for %s: %s", rec["git_url"], e)
                    import_failed = True
                    out.append(_skip_record(spec, "*", f"import: {e}"))
                    continue
            snap = Snapshot(
                date=rec["snapshot_date"],
                commit_hash=rec["commit_hash"],
                committed_at=rec.get("committed_at"),
            )
            out.append(_submit_analysis(
                client, org_id, project_id, analyzer_id, spec, rec["branch"], snap,
                knowledge_asof=knowledge_asof,
            ))
        return out

    pending: list[AnalysisRecord] = []
    appended = Counter()
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_process, items) for items in work.values()]
        # Submission (not completion) order, as in import_and_schedule: rows
        # land grouped per project, in source-manifest order — deterministic.
        for future in futures:
            for rec_out in future.result():
                _append_record(data_dir, rec_out)
                appended[rec_out.status] += 1
                if rec_out.status != "skipped":
                    pending.append(rec_out)

    log.info(
        "resubmit-frozen: appended %d record(s) (%s) to %s",
        sum(appended.values()), dict(appended), _manifest_path(data_dir),
    )
    return pending


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
    denylist = load_denylist(data_dir)

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
                    rec["terminal_at"] = _utcnow_iso()
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
                    _persist_results(client, org_id, rec, data_dir, analysis)
                else:
                    rec["error"] = _failure_reason(client, org_id, rec, analysis)
                    _persist_results(client, org_id, rec, data_dir, analysis)
                    log.info(
                        "analysis %s terminated status=%s: %s",
                        rec["analysis_id"], status, rec["error"],
                    )
                    # An unresolvable commit re-fails identically on every
                    # re-drive — denylist it so submit/retry stop re-driving it.
                    if is_unresolvable_reason(rec.get("error")):
                        key = (rec.get("git_url"), rec.get("snapshot_date"))
                        if key not in denylist:
                            denylist[key] = record_unresolvable(data_dir, rec, rec["error"])
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
                rec["terminal_at"] = _utcnow_iso()
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


def poll_with_retries(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
    data_dir: Path,
    auto_retry: int = 2,
    ignore_denylist: bool = False,
) -> None:
    """poll_and_collect, then up to `auto_retry` retry+poll passes.

    After each convergence, sad-terminal rows are re-driven through
    retry_failed (which honours the denylist unless ignore_denylist) and polled
    again. Stops early once no retryable rows remain or a pass re-submits
    nothing (everything left is denylisted or unrebuildable).
    """
    poll_and_collect(client, org_id, data_dir)
    for attempt in range(1, auto_retry + 1):
        path = _manifest_path(data_dir)
        if not path.exists():
            return
        records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        retryable = [r for r in records if r.get("status") in RETRYABLE_STATUSES]
        if not retryable:
            log.info("auto-retry: no retryable rows — done after %d pass(es)", attempt - 1)
            return
        log.info(
            "auto-retry pass %d/%d: %d sad-terminal row(s) to re-drive",
            attempt, auto_retry, len(retryable),
        )
        resubmitted = retry_failed(
            client, org_id, analyzer_id, data_dir, ignore_denylist=ignore_denylist,
        )
        log.info(
            "auto-retry pass %d/%d: resubmitted %d of %d row(s)",
            attempt, auto_retry, len(resubmitted), len(retryable),
        )
        if not resubmitted:
            return
        poll_and_collect(client, org_id, data_dir)


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
    analysis: dict | None = None,
) -> None:
    out_dir = data_dir / "raw" / rec["project_id"] / rec["analysis_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    if analysis is not None:
        # The terminal analysis document itself — its steps carry the per-step
        # Started_on/Ended_on stamps that collect.py turns into timing columns.
        (out_dir / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
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
