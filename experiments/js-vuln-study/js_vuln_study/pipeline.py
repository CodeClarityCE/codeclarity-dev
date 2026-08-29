"""The study's state machine: provision -> submit -> poll -> retry -> collect.

One manifest row per (git_url, snapshot_date). `run()` computes every missing
key from the sample (or from another study's `frozen_from` manifest) BEFORE
any GitHub call, so a fully-covered project costs zero calls on a resumed
run; submits serially per project so a Ctrl-C loses at most one project's
POSTs; polls a project's whole pending batch in one or two calls instead of
one GET per analysis; and never gives up on a *server*-terminal state (the
dispatcher reaper retires wedged work on its own, except `updating_db`, which
it never touches, so poll keeps one client-side ceiling for that case).
"""

from __future__ import annotations

import json
import logging
import random
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import collect, github, manifest, sample
from .client import CodeClarityClient, CodeClarityError
from .config import Settings, Study

log = logging.getLogger(__name__)

POLL_INITIAL = 10.0
POLL_MAX = 120.0
NO_PROGRESS_WARN_SECONDS = 45 * 60  # dead plugin consumer (RabbitMQ mgmt UI) signal
DEFAULT_GIVE_UP_HOURS = 30  # past the server reaper's RECOVERY_MAX_AGE (24h)

PLUGIN_TYPES = ("js-sbom", "vuln-finder", "license-finder")  # probed for a failure reason
PERSIST_PLUGINS = ("js-sbom", "vuln-finder")  # the only blobs collect.py reads

TERMINAL_HAPPY = {"completed", "success"}
TERMINAL_SAD = {"failure", "failed", "cancelled"}


@dataclass(frozen=True)
class Snapshot:
    date: str  # "YYYY-MM-DD" or "HEAD"
    commit_hash: str | None
    committed_at: str | None


class ProjectUnresolvable(Exception):
    pass


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# Provisioning + provenance
# --------------------------------------------------------------------------- #


def provision(client: CodeClarityClient, study: Study, settings: Settings) -> tuple[str, str, str]:
    if not settings.github_token:
        raise SystemExit(
            "GITHUB_TOKEN not set: a classic PAT with scope `public_repo` is "
            "required to import projects as git (not FILE uploads)."
        )
    return client.provision(
        study.org_name, study.analyzer_name, study.plugin_versions, settings.github_token
    )


def _git(repo: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _api_version(repo_root: Path) -> str | None:
    try:
        pkg = json.loads((repo_root / "api" / "package.json").read_text(encoding="utf-8"))
        return pkg.get("version")
    except (OSError, json.JSONDecodeError):
        return None


def _analyzer_steps(
    client: CodeClarityClient, org_id: str, analyzer_id: str, analyzer_name: str
) -> list[list[dict]] | None:
    """The analyzer's *actual* steps, read back from the API: plugin_versions
    only applies to a newly-created analyzer."""
    try:
        analyzer = client.get_analyzer_by_name(org_id, analyzer_name)
    except CodeClarityError as e:
        log.warning("analyzer read-back failed: %s", e)
        return None
    if analyzer is None:
        return None
    return [
        [{"name": s.get("name"), "version": s.get("version")} for s in (stage or [])]
        for stage in (analyzer.get("steps") or [])
    ]


def record_provenance(
    client: CodeClarityClient,
    study: Study,
    org_id: str,
    analyzer_id: str,
    cmd: str,
    extra: dict | None = None,
) -> dict:
    repo_root = Path(__file__).resolve().parents[3]
    try:
        knowledge = client.get_knowledge_provenance()
    except CodeClarityError as e:
        log.warning("GET /knowledge/provenance failed: %s", e)
        knowledge = {"knowledge_sources": None, "epss_rows": None}
    meta: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(uuid.uuid4()),
        "experiment_sha": _git(repo_root, "rev-parse", "HEAD"),
        "experiment_dirty": bool(_git(repo_root, "status", "--porcelain") or ""),
        "api_sha": _git(repo_root / "api", "rev-parse", "HEAD"),
        "backend_sha": _git(repo_root / "backend", "rev-parse", "HEAD"),
        "api_version": _api_version(repo_root),
        "org_id": org_id,
        "analyzer_id": analyzer_id,
        "analyzer_steps": _analyzer_steps(client, org_id, analyzer_id, study.analyzer_name),
        "knowledge": knowledge,
        "config": {"snapshot_dates": study.grid, "knowledge_asof": study.knowledge_asof},
        "cmd": cmd,
    }
    if extra:
        meta.update(extra)
    path = study.run_meta_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(meta) + "\n")
    log.info("run meta recorded (run_id=%s) to %s", meta["run_id"], path)
    return meta


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #


def _resolve_project(
    http: httpx.Client, owner: str, repo: str, dates: list[str]
) -> tuple[str, list[Snapshot], Snapshot | None, str | None]:
    """Returns (branch, dated_snapshots, head_snapshot_or_none, head_error).

    A repo that doesn't resolve, has no default branch, or errors while
    resolving a DATED commit raises `ProjectUnresolvable` (project-wide skip:
    shared infra work, so any error there is treated conservatively). A
    failed HEAD lookup is NOT project-wide: it is reported back as
    `head_error` so the caller can record a single skipped HEAD row while the
    dated snapshots still submit normally.
    """
    meta = github.get_repo(http, owner, repo)
    if meta is None:
        raise ProjectUnresolvable("repo not found")
    branch = meta.get("default_branch")
    if not branch:
        raise ProjectUnresolvable("no default branch")

    dated: list[Snapshot] = []
    for d in dates:
        iso = f"{d}T00:00:00+00:00"
        try:
            result = github.commit_before(http, owner, repo, branch, iso)
        except httpx.HTTPStatusError as e:
            raise ProjectUnresolvable(f"snapshot resolution failed: {e}") from e
        if result is None:
            continue  # repo didn't exist yet at this date
        sha, committed_at = result
        dated.append(Snapshot(d, sha, committed_at))

    head_snap: Snapshot | None = None
    head_error: str | None = None
    try:
        result = github.commit_before(http, owner, repo, branch, None)
        if result is None:
            head_error = "no commits on default branch"
        else:
            sha, committed_at = result
            head_snap = Snapshot("HEAD", sha, committed_at)
    except Exception as e:  # noqa: BLE001 (a HEAD failure must not fail the project)
        head_error = str(e)

    return branch, dated, head_snap, head_error


# --------------------------------------------------------------------------- #
# Submit
# --------------------------------------------------------------------------- #


def _ensure_project(
    client: CodeClarityClient,
    org_id: str,
    git_url: str,
    npm_name: str,
    description: str,
    project_ids: dict[str, str],
    integration_id: str,
) -> str:
    project_id = project_ids.get(git_url)
    if project_id is None:
        project_id = client.import_project(
            org_id, git_url, name=npm_name, description=description, integration_id=integration_id
        )
        project_ids[git_url] = project_id
    return project_id


def _skip_row(npm_name: str, tier: str, rank: int, git_url: str, snapshot_date: str, reason: str) -> manifest.Row:
    return manifest.Row(
        npm_name=npm_name, tier=tier, rank=rank, git_url=git_url,
        snapshot_date=snapshot_date, state="skipped", error=reason,
    )


def _submit_one(
    client: CodeClarityClient,
    org_id: str,
    project_id: str,
    analyzer_id: str,
    npm_name: str,
    tier: str,
    rank: int,
    git_url: str,
    branch: str,
    snap: Snapshot,
    knowledge_asof: str | None,
    run_id: str | None,
) -> manifest.Row:
    config = {"vuln-finder": {"knowledge_asof": knowledge_asof}} if knowledge_asof else None
    try:
        analysis_id = client.start_analysis(
            org_id=org_id, project_id=project_id, analyzer_id=analyzer_id,
            branch=branch, commit_hash=snap.commit_hash, config=config,
        )
        state, error = "pending", None
    except CodeClarityError as e:
        analysis_id, state, error = None, "failed", f"submit: {e}"
        log.warning("start_analysis failed for %s@%s: %s", npm_name, snap.date, e)
    return manifest.Row(
        npm_name=npm_name, tier=tier, rank=rank, git_url=git_url, branch=branch,
        snapshot_date=snap.date, commit_hash=snap.commit_hash, committed_at=snap.committed_at,
        project_id=project_id, analysis_id=analysis_id, state=state, error=error,
        knowledge_asof=knowledge_asof, run_id=run_id, submitted_at=_utcnow_iso(),
    )


def submit_missing(
    client: CodeClarityClient,
    study: Study,
    settings: Settings,
    org_id: str,
    analyzer_id: str,
    integration_id: str,
    specs: list[sample.ProjectSpec],
    existing_keys: set[tuple[str, str]],
    project_ids: dict[str, str],
    run_id: str,
    limit: int | None = None,
) -> list[manifest.Row]:
    """Compute missing (git_url, snapshot_date) keys before any GitHub call,
    then resolve + import + POST per project, serially. A Ctrl-C loses at
    most one in-flight project's POSTs; a resumed run over a fully-covered
    sample makes zero GitHub calls."""
    if limit:
        specs = specs[:limit]
    dates = study.grid if study.snapshots else []
    new_rows: list[manifest.Row] = []
    http = github.make_client(github.GITHUB_API, settings.github_token)
    try:
        for spec in specs:
            wanted = {(spec.git_url, d) for d in dates} | {(spec.git_url, "HEAD")}
            if wanted <= existing_keys:
                continue
            try:
                branch, dated, head_snap, head_error = _resolve_project(
                    http, spec.github_owner, spec.github_repo, dates
                )
            except ProjectUnresolvable as e:
                if (spec.git_url, "*") not in existing_keys:
                    row = _skip_row(spec.npm_name, study.name, spec.rank, spec.git_url, "*", str(e))
                    new_rows.append(row)
                    existing_keys.add(("*", "*"))  # not a real key; prevents dup logging below
                continue

            try:
                project_id = _ensure_project(
                    client, org_id, spec.git_url, spec.npm_name,
                    f"{study.name} rank={spec.rank}", project_ids, integration_id,
                )
            except CodeClarityError as e:
                row = _skip_row(spec.npm_name, study.name, spec.rank, spec.git_url, "*", f"import: {e}")
                new_rows.append(row)
                continue

            for snap in dated:
                key = (spec.git_url, snap.date)
                if key in existing_keys:
                    continue
                row = _submit_one(
                    client, org_id, project_id, analyzer_id, spec.npm_name, study.name,
                    spec.rank, spec.git_url, branch, snap, study.knowledge_asof, run_id,
                )
                new_rows.append(row)
                existing_keys.add(key)

            head_key = (spec.git_url, "HEAD")
            if head_key not in existing_keys:
                if head_snap is not None:
                    row = _submit_one(
                        client, org_id, project_id, analyzer_id, spec.npm_name, study.name,
                        spec.rank, spec.git_url, branch, head_snap, study.knowledge_asof, run_id,
                    )
                else:
                    row = _skip_row(
                        spec.npm_name, study.name, spec.rank, spec.git_url, "HEAD",
                        f"head-resolution: {head_error}",
                    )
                new_rows.append(row)
                existing_keys.add(head_key)
    finally:
        http.close()
    return new_rows


def submit_frozen(
    client: CodeClarityClient,
    study: Study,
    org_id: str,
    analyzer_id: str,
    integration_id: str,
    source_manifest_path: Path,
    existing_keys: set[tuple[str, str]],
    project_ids: dict[str, str],
    run_id: str,
) -> list[manifest.Row]:
    """Re-submit another study's `done` rows commit-pinned at their archived
    SHAs, deduped by (git_url, commit_hash) so an identical tree pinned by
    several snapshot dates is scanned once. The source manifest is read-only
    and never re-resolved through GitHub. This is how a ladder rung or a
    cohort re-scan under a different `knowledge_asof` works."""
    source_rows = manifest.read(source_manifest_path)
    new_rows: list[manifest.Row] = []
    seen_sha: set[tuple[str, str]] = set()
    for r in source_rows:
        if r.state != "done":
            continue
        key = (r.git_url, r.snapshot_date)
        if not r.commit_hash:
            if key not in existing_keys:
                new_rows.append(_skip_row(r.npm_name, study.name, r.rank, r.git_url, r.snapshot_date, "no pinned commit in source"))
                existing_keys.add(key)
            continue
        sha_key = (r.git_url, r.commit_hash)
        if sha_key in seen_sha:
            continue
        seen_sha.add(sha_key)
        if key in existing_keys:
            continue
        try:
            project_id = _ensure_project(
                client, org_id, r.git_url, r.npm_name,
                f"{study.name} frozen_from", project_ids, integration_id,
            )
        except CodeClarityError as e:
            new_rows.append(_skip_row(r.npm_name, study.name, r.rank, r.git_url, r.snapshot_date, f"import: {e}"))
            continue
        snap = Snapshot(r.snapshot_date, r.commit_hash, r.committed_at)
        row = _submit_one(
            client, org_id, project_id, analyzer_id, r.npm_name, study.name, r.rank,
            r.git_url, r.branch or "main", snap, study.knowledge_asof, run_id,
        )
        new_rows.append(row)
        existing_keys.add(key)
    return new_rows


# --------------------------------------------------------------------------- #
# Poll
# --------------------------------------------------------------------------- #


def _failure_reason(client: CodeClarityClient, org_id: str, row: manifest.Row, analysis: dict) -> str:
    reason = (analysis.get("failure_reason") or "").strip()
    if reason:
        return reason
    failed_steps = [
        s.get("name")
        for stage in (analysis.get("steps") or [])
        for s in (stage or [])
        if s.get("status") in TERMINAL_SAD and s.get("name")
    ]
    for plugin in (failed_steps or PLUGIN_TYPES):
        try:
            blob = client.get_result(org_id, row.project_id, row.analysis_id, plugin)
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


def _persist_results(client: CodeClarityClient, org_id: str, row: manifest.Row, study: Study) -> None:
    out_dir = study.raw_dir / row.project_id / row.analysis_id
    out_dir.mkdir(parents=True, exist_ok=True)
    for plugin in PERSIST_PLUGINS:
        try:
            blob = client.get_result(org_id, row.project_id, row.analysis_id, plugin)
        except CodeClarityError as e:
            log.info("no %s result for %s (%s)", plugin, row.analysis_id, e)
            continue
        (out_dir / f"{plugin}.json").write_text(json.dumps(blob), encoding="utf-8")


def poll(client: CodeClarityClient, study: Study, org_id: str, give_up_hours: int = DEFAULT_GIVE_UP_HOURS) -> None:
    """Drive every pending row to a terminal state.

    Batches by project (one `list_project_analyses` call covers a project's
    whole pending set instead of one GET per analysis). Never gives up on a
    server-terminal state; the one client-side ceiling (`give_up_hours`, past
    the dispatcher reaper's RECOVERY_MAX_AGE) exists only for `updating_db`,
    the one state the reaper never retires. A transport error (a `make down &&
    make up` mid-poll) is logged and retried on the next pass rather than
    crashing the command.
    """
    rows = manifest.read(study.manifest_path)
    by_project: dict[str, list[int]] = {}
    for i, r in enumerate(rows):
        if r.state == "pending" and r.analysis_id and r.project_id:
            by_project.setdefault(r.project_id, []).append(i)
    if not by_project:
        return
    log.info(
        "polling %d pending analyses across %d projects",
        sum(len(v) for v in by_project.values()), len(by_project),
    )
    first_seen = {i: time.time() for idxs in by_project.values() for i in idxs}
    last_summary = time.time()
    last_progress = time.time()
    wait = POLL_INITIAL

    while by_project:
        progressed = False
        statuses: dict[str, int] = {}
        for project_id in list(by_project):
            idxs = by_project[project_id]
            try:
                analyses = client.list_project_analyses(org_id, project_id)
            except CodeClarityError as e:
                log.warning("could not list analyses for project %s: %s", project_id, e)
                continue
            by_id = {a.get("id"): a for a in analyses}
            still: list[int] = []
            for i in idxs:
                row = rows[i]
                analysis = by_id.get(row.analysis_id)
                if analysis is None:
                    row.state = "failed"
                    row.error = "analysis not found (deleted server-side?)"
                    row.terminal_at = _utcnow_iso()
                    progressed = True
                    manifest.write_all(study.manifest_path, rows)
                    continue
                status = analysis.get("status")
                statuses[status or "?"] = statuses.get(status or "?", 0) + 1
                if status in TERMINAL_HAPPY or status in TERMINAL_SAD:
                    progressed = True
                    row.server_status = status
                    row.state = "done" if status in TERMINAL_HAPPY else "failed"
                    _persist_results(client, org_id, row, study)
                    if row.state == "failed":
                        row.error = _failure_reason(client, org_id, row, analysis)
                    row.terminal_at = _utcnow_iso()
                    manifest.write_all(study.manifest_path, rows)
                elif time.time() - first_seen[i] > give_up_hours * 3600:
                    row.state = "failed"
                    row.server_status = status
                    row.error = (
                        f"client ceiling: no terminal status after {give_up_hours}h "
                        f"(server_status={status})"
                    )
                    row.terminal_at = _utcnow_iso()
                    progressed = True
                    manifest.write_all(study.manifest_path, rows)
                else:
                    still.append(i)
            if still:
                by_project[project_id] = still
            else:
                del by_project[project_id]

        if by_project:
            total_active = sum(len(v) for v in by_project.values())
            now = time.time()
            if now - last_summary > 30:
                log.info(
                    "waiting on %d analyses across %d projects; statuses=%s",
                    total_active, len(by_project), statuses,
                )
                last_summary = now
            if progressed:
                last_progress = now
            elif now - last_progress > NO_PROGRESS_WARN_SECONDS:
                log.warning(
                    "no transitions in the last %d min - check for a dead plugin "
                    "consumer (RabbitMQ management UI, http://localhost:15672: a "
                    "dispatcher_<plugin> queue with consumers=0)",
                    NO_PROGRESS_WARN_SECONDS // 60,
                )
                last_progress = now  # avoid repeating every pass
            time.sleep(min(POLL_MAX, wait) * random.uniform(0.8, 1.2))
            wait = min(POLL_MAX, wait * 1.5)


# --------------------------------------------------------------------------- #
# Retry / refresh-head
# --------------------------------------------------------------------------- #


def retry(client: CodeClarityClient, study: Study, org_id: str, analyzer_id: str) -> int:
    """Re-drive every eligible failed row in place: `attempts < study.retries`
    and the error doesn't carry the downloader's `CommitUnresolvable` marker
    (which the current backend also writes for transient clone failures, so
    it is a retry-budget question, not a permanent-skip one; `retry_one`
    with `force=True` is the escape hatch for a row this policy won't touch).
    Retries with the ROW's own `knowledge_asof`, never the study's current
    value, so a rung's auto-retry never re-drives without its dose."""
    rows = manifest.read(study.manifest_path)
    eligible = [
        i for i, r in enumerate(rows)
        if r.state == "failed" and r.project_id and r.branch
        and r.attempts < study.retries
        and "CommitUnresolvable" not in (r.error or "")
    ]
    for i in eligible:
        r = rows[i]
        snap = Snapshot(r.snapshot_date, r.commit_hash, r.committed_at)
        new_row = _submit_one(
            client, org_id, r.project_id, analyzer_id, r.npm_name, r.tier, r.rank,
            r.git_url, r.branch, snap, r.knowledge_asof, r.run_id,
        )
        new_row.attempts = r.attempts + 1
        rows[i] = new_row
        manifest.write_all(study.manifest_path, rows)
    return len(eligible)


def retry_one(
    client: CodeClarityClient,
    study: Study,
    org_id: str,
    analyzer_id: str,
    npm_name: str,
    snapshot_date: str | None = None,
    force: bool = False,
) -> int:
    """`run --retry SLUG[@DATE] [--force]`: re-drive one failed row, ignoring
    the attempts cap and the CommitUnresolvable marker when `force` is set."""
    rows = manifest.read(study.manifest_path)
    n = 0
    for i, r in enumerate(rows):
        if r.npm_name != npm_name or r.state != "failed":
            continue
        if snapshot_date is not None and r.snapshot_date != snapshot_date:
            continue
        if not r.project_id or not r.branch:
            log.warning("cannot retry %s@%s: no project_id/branch recorded", r.npm_name, r.snapshot_date)
            continue
        if not force and (
            "CommitUnresolvable" in (r.error or "") or r.attempts >= study.retries
        ):
            log.warning(
                "%s@%s is not eligible for retry (attempts=%d, error=%r); pass --force to override",
                r.npm_name, r.snapshot_date, r.attempts, r.error,
            )
            continue
        snap = Snapshot(r.snapshot_date, r.commit_hash, r.committed_at)
        new_row = _submit_one(
            client, org_id, r.project_id, analyzer_id, r.npm_name, r.tier, r.rank,
            r.git_url, r.branch, snap, r.knowledge_asof, r.run_id,
        )
        new_row.attempts = r.attempts + 1
        rows[i] = new_row
        manifest.write_all(study.manifest_path, rows)
        n += 1
    return n


def refresh_head(
    client: CodeClarityClient, study: Study, org_id: str, analyzer_id: str,
    settings: Settings, dry_run: bool = False,
) -> int:
    """Re-resolve and re-submit every project's HEAD row in place, so a
    cross-cohort comparison's HEAD trees are scanned the same day."""
    rows = manifest.read(study.manifest_path)
    http = github.make_client(github.GITHUB_API, settings.github_token)
    refreshed = 0
    try:
        for i, r in enumerate(rows):
            if r.snapshot_date != "HEAD" or not r.project_id or not r.branch:
                continue
            owner_repo = github.parse_owner_repo(r.git_url)
            if not owner_repo:
                continue
            try:
                result = github.commit_before(http, *owner_repo, r.branch, None)
            except Exception as e:  # noqa: BLE001
                log.warning("HEAD refresh failed for %s: %s", r.git_url, e)
                continue
            if result is None:
                continue
            sha, committed_at = result
            if dry_run:
                log.info("[dry-run] would refresh-head %s -> %s", r.npm_name, sha[:12])
                continue
            snap = Snapshot("HEAD", sha, committed_at)
            new_row = _submit_one(
                client, org_id, r.project_id, analyzer_id, r.npm_name, r.tier, r.rank,
                r.git_url, r.branch, snap, study.knowledge_asof, r.run_id,
            )
            rows[i] = new_row
            refreshed += 1
            manifest.write_all(study.manifest_path, rows)
    finally:
        http.close()
    return refreshed


# --------------------------------------------------------------------------- #
# clean
# --------------------------------------------------------------------------- #


def clean(client: CodeClarityClient, study: Study, org_id: str, dry_run: bool = False) -> int:
    """Batch-delete every project this study's manifest knows about (the API
    cancels in-flight analyses and removes the clone tree itself), then
    archive the manifest so a later `run` re-imports fresh project ids
    instead of POSTing at deleted ones."""
    rows = manifest.read(study.manifest_path)
    project_ids = sorted({r.project_id for r in rows if r.project_id})
    if not project_ids:
        log.info("nothing to clean for study %s", study.name)
        return 0
    if dry_run:
        log.info("[dry-run] would delete %d project(s) in org %s", len(project_ids), org_id)
        return len(project_ids)
    client.delete_projects(org_id, project_ids)
    if study.manifest_path.exists():
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        study.manifest_path.rename(study.manifest_path.with_name(f"manifest.{ts}.jsonl"))
    log.info("deleted %d project(s) in org %s; manifest archived", len(project_ids), org_id)
    return len(project_ids)


# --------------------------------------------------------------------------- #
# run()
# --------------------------------------------------------------------------- #


def run(
    client: CodeClarityClient,
    study: Study,
    settings: Settings,
    limit: int | None = None,
    refresh_head_flag: bool = False,
    retry_target: str | None = None,
    retry_force: bool = False,
    dry_run: bool = False,
    give_up_hours: int = DEFAULT_GIVE_UP_HOURS,
) -> None:
    """provision -> submit missing rows -> poll -> retry -> poll -> collect.

    Resumable and idempotent: re-running the same command only touches rows
    that are pending or eligible for retry. `--refresh-head` and `--retry`
    are one-shot alternate modes that skip the submit/poll/collect sequence.
    """
    org_id, analyzer_id, integration_id = provision(client, study, settings)

    if refresh_head_flag:
        refresh_head(client, study, org_id, analyzer_id, settings, dry_run=dry_run)
        if not dry_run:
            record_provenance(client, study, org_id, analyzer_id, "refresh-head")
        return

    if retry_target:
        npm_name, _, date_part = retry_target.partition("@")
        n = retry_one(client, study, org_id, analyzer_id, npm_name, date_part or None, force=retry_force)
        log.info("retried %d row(s) matching %s", n, retry_target)
        return

    rows = manifest.read(study.manifest_path)
    existing_keys = {r.key() for r in rows}
    project_ids = {r.git_url: r.project_id for r in rows if r.project_id}
    run_id = str(uuid.uuid4())[:8]

    if study.frozen_from:
        new_rows = submit_frozen(
            client, study, org_id, analyzer_id, integration_id,
            study.frozen_from, existing_keys, project_ids, run_id,
        )
    else:
        specs = sample.load_sample(study.sample_path)
        new_rows = submit_missing(
            client, study, settings, org_id, analyzer_id, integration_id,
            specs, existing_keys, project_ids, run_id, limit=limit,
        )

    if dry_run:
        log.info("[dry-run] would submit %d new row(s)", len(new_rows))
        return

    for r in new_rows:
        manifest.append(study.manifest_path, r)
    if new_rows:
        record_provenance(
            client, study, org_id, analyzer_id, "submit",
            extra={"knowledge_asof": study.knowledge_asof},
        )

    poll(client, study, org_id, give_up_hours=give_up_hours)
    n_retried = retry(client, study, org_id, analyzer_id)
    if n_retried:
        log.info("retry: re-drove %d row(s)", n_retried)
        poll(client, study, org_id, give_up_hours=give_up_hours)

    collect.build_tables(study)
