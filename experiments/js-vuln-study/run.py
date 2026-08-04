"""CLI entry point for the JS vulnerability-evolution experiment.

Subcommands:
  sample    — build the popularity-stratified project list
  smoke     — run a single-project HEAD-only scan (verification gate)
  submit    — import every project in the sample and submit all analyses
  poll      — poll all in-flight analyses and persist their results, then
              auto-retry sad-terminal rows (--auto-retry passes, default 2)
  retry     — re-submit sad-terminal manifest rows (failed/failure/cancelled/
              failed-submit), replacing each row in place
  collect   — flatten raw blobs into Parquet tables
  triangulate — cross-check a stratified HEAD subsample against independent
              scanners (npm audit, osv-scanner)
  clean     — bulk-delete the org's projects/analyses (backlog clear), and/or
              sweep the downloader's on-disk clones (--clones / --clones-only)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover — dotenv is optional for CLI help
    def load_dotenv() -> None:  # type: ignore[misc]
        return None

from js_vuln_study.client import CodeClarityClient, CodeClarityError
from js_vuln_study.collect import build_tables
from js_vuln_study.orchestrator import (
    DENYLIST_FILENAME,
    RETRYABLE_STATUSES,
    import_and_schedule,
    poll_and_collect,
    poll_with_retries,
    retry_failed,
)
from js_vuln_study.provenance import capture_run_meta
from js_vuln_study.reclaim import clone_root, leaf_for, sweep
from js_vuln_study.sample import ProjectSpec, build_sample, load_sample

log = logging.getLogger("js_vuln_study.run")

DATA_DIR = Path(__file__).resolve().parent / "data"
SAMPLE_PATH = DATA_DIR / "sample.json"
SETUP_CACHE = DATA_DIR / "setup.json"
PROBE_CACHE = DATA_DIR / "repo_probe_cache.jsonl"


def _client() -> CodeClarityClient:
    base = os.environ.get("CC_BASE_URL", "https://localhost/api")
    email = os.environ["CC_EMAIL"]
    password = os.environ["CC_PASSWORD"]
    verify = os.environ.get("CC_VERIFY_TLS", "false").lower() == "true"
    return CodeClarityClient(base, email, password, verify_tls=verify)


def _ensure_setup(client: CodeClarityClient) -> tuple[str, str, str]:
    """Return (org_id, analyzer_id, integration_id), cached in data/setup.json.

    The client-side dedupe on org name is unreliable (list shape quirks),
    which previously caused poll runs to hit 403 because a fresh org was
    provisioned on every invocation. We persist the IDs from the first
    successful setup and reuse them on later runs. NB: the cache wins over the
    JS_VULN_ORG_NAME / JS_VULN_ANALYZER_NAME env overrides — delete
    data/setup.json to re-provision after changing the names.
    """
    import json as _json

    if SETUP_CACHE.exists():
        cached = _json.loads(SETUP_CACHE.read_text())
        return cached["org_id"], cached["analyzer_id"], cached["integration_id"]

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit(
            "GITHUB_TOKEN not set — a classic PAT with scope `public_repo` is "
            "required to import projects as git (not FILE uploads)."
        )
    org_id = client.ensure_org(
        name=os.environ.get("JS_VULN_ORG_NAME", "js-vuln-study-2026"),
        description="Popularity-stratified study of JS vulnerability evolution.",
    )
    analyzer_id = client.ensure_js_analyzer(
        org_id,
        name=os.environ.get("JS_VULN_ANALYZER_NAME", "js-vuln-study-v2"),
    )
    integration_id = client.ensure_github_integration(org_id, token)
    SETUP_CACHE.parent.mkdir(parents=True, exist_ok=True)
    SETUP_CACHE.write_text(_json.dumps({
        "org_id": org_id,
        "analyzer_id": analyzer_id,
        "integration_id": integration_id,
    }, indent=2))
    return org_id, analyzer_id, integration_id


def cmd_sample(args: argparse.Namespace) -> int:
    if args.refresh:
        PROBE_CACHE.unlink(missing_ok=True)
    build_sample(
        limit=args.limit,
        output=SAMPLE_PATH,
        probe_cache=PROBE_CACHE,
        min_npm_downloads=args.min_npm_downloads,
    )
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    # vuejs/core commits pnpm-lock.yaml so js-sbom resolves a real dep tree.
    # Many top-ranked libraries (express, lodash, …) deliberately omit lockfiles
    # from their repos, which js-sbom reports as "0 dependencies".
    spec = ProjectSpec(
        npm_name="@vue/runtime-core",
        rank=0,
        tier="top-100",
        git_url="https://github.com/vuejs/core",
        github_owner="vuejs",
        github_repo="core",
        default_branch="main",
    )
    with _client() as client:
        org_id, analyzer_id, integration_id = _ensure_setup(client)
        import_and_schedule(
            client, org_id, analyzer_id, [spec], DATA_DIR,
            integration_id=integration_id, skip_head_only=True,
        )
        capture_run_meta(client, org_id, analyzer_id, DATA_DIR, extra={"cmd": "smoke"})
        poll_and_collect(client, org_id, DATA_DIR)
    return 0


def cmd_submit(args: argparse.Namespace) -> int:
    specs = load_sample(SAMPLE_PATH)
    if args.limit:
        specs = specs[: args.limit]
    with _client() as client:
        org_id, analyzer_id, integration_id = _ensure_setup(client)
        import_and_schedule(
            client, org_id, analyzer_id, specs, DATA_DIR,
            integration_id=integration_id, skip_head_only=not args.snapshots,
            ignore_denylist=args.ignore_denylist,
        )
        capture_run_meta(
            client, org_id, analyzer_id, DATA_DIR,
            extra={"cmd": "submit", "sample_limit": args.limit, "snapshots": args.snapshots},
        )
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    with _client() as client:
        org_id, analyzer_id, _ = _ensure_setup(client)
        poll_with_retries(
            client, org_id, analyzer_id, DATA_DIR,
            auto_retry=args.auto_retry, ignore_denylist=args.ignore_denylist,
        )
    return 0


def cmd_retry(args: argparse.Namespace) -> int:
    statuses = {s.strip() for s in args.status.split(",") if s.strip()}
    with _client() as client:
        org_id, analyzer_id, _ = _ensure_setup(client)
        retry_failed(
            client, org_id, analyzer_id, DATA_DIR,
            statuses=statuses, date=args.date, project=args.project,
            dry_run=args.dry_run, ignore_denylist=args.ignore_denylist,
        )
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    build_tables(DATA_DIR, include_deps=not args.no_deps)
    return 0


def cmd_triangulate(args: argparse.Namespace) -> int:
    from js_vuln_study.triangulate import run_triangulation

    out = Path(args.out) if args.out else DATA_DIR / "tables" / "triangulation.parquet"
    return run_triangulation(DATA_DIR, n=args.n, out=out, dry_run=args.dry_run)


def _clone_keep_set(
    client: CodeClarityClient,
    org_id: str,
) -> set[tuple[str, str]]:
    """(project_id, leaf) pairs whose clone must survive a sweep.

    Two sources, both conservative:
      1. Manifest rows still marked 'submitted' — analyses in flight right now.
      2. Projects that still exist server-side but have no terminal manifest row
         for that leaf. Such a project may have analyses this manifest doesn't
         know about (submitted by another run), so its clones are left alone.

    Everything else — notably leaves under projects that no longer exist
    server-side — is an orphan from an earlier run and is reclaimable.
    """
    manifest = DATA_DIR / "manifest.jsonl"
    keep: set[tuple[str, str]] = set()
    settled: set[tuple[str, str]] = set()
    if manifest.exists():
        import json as _json

        for line in manifest.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = _json.loads(line)
            project_id = rec.get("project_id")
            leaf = leaf_for(rec.get("commit_hash"), rec.get("branch"))
            if not (project_id and leaf):
                continue
            if rec.get("status") == "submitted":
                keep.add((project_id, leaf))
            else:
                settled.add((project_id, leaf))

    try:
        live_project_ids = {p["id"] for p in client.list_projects(org_id)}
    except CodeClarityError as e:
        # Without the server's view we can't tell an orphan from a live project,
        # so fall back to "keep everything the manifest hasn't settled".
        log.warning("could not list projects (%s); sweeping manifest-settled leaves only", e)
        return keep

    root = clone_root()
    if root is None:
        return keep
    projects_dir = root / org_id / "projects"
    if projects_dir.is_dir():
        for project_dir in projects_dir.iterdir():
            if not project_dir.is_dir() or project_dir.name not in live_project_ids:
                continue
            for leaf_dir in project_dir.iterdir():
                if not leaf_dir.is_dir():
                    continue
                key = (project_dir.name, leaf_dir.name)
                if key not in settled:
                    keep.add(key)
    return keep


def cmd_clean(args: argparse.Namespace) -> int:
    """Bulk-clear the study org's backlog of projects (and their analyses),
    and/or sweep the downloader's clone tree on disk.

    Uses the API's batch-delete endpoint, which auto-cancels in-flight analyses
    and removes them in bounded batches — no per-project DELETE storm.

    The clone sweep (--clones / --clones-only) reclaims checkouts the backend
    never deletes on its own. --clones-only is the one to reach for mid-run: it
    frees disk without destroying the backlog.
    """
    with _client() as client:
        org_id, _, _ = _ensure_setup(client)

        if args.clones or args.clones_only:
            if clone_root() is None:
                log.warning("clone sweep skipped: clone tree not visible from here")
            else:
                keep = _clone_keep_set(client, org_id)
                rep = sweep(org_id, keep, dry_run=args.dry_run)
                prefix = "[dry-run] would reclaim" if args.dry_run else "reclaimed"
                log.info(
                    "%s %d of %d clone dir(s), %.2f GB",
                    prefix, len(rep.deleted), rep.scanned, rep.bytes_freed / 1e9,
                )
                if rep.kept:
                    log.info("kept: %s", rep.kept_by_reason())
        if args.clones_only:
            return 0

        if args.ids:
            project_ids = [pid.strip() for pid in args.ids.split(",") if pid.strip()]
        else:
            projects = client.list_projects(org_id)
            project_ids = [p["id"] for p in projects]
            if args.limit:
                project_ids = project_ids[: args.limit]

        if not project_ids:
            log.info("nothing to clean — no projects found")
            return 0

        if args.dry_run:
            log.info("[dry-run] would delete %d project(s) in org %s", len(project_ids), org_id)
            return 0

        log.info("deleting %d project(s) in org %s", len(project_ids), org_id)
        results = client.delete_projects(org_id, project_ids, batch_size=args.batch_size)

        by_status: dict[str, int] = {}
        for r in results:
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        log.info("clean complete: %s", by_status)
    return 0


def main() -> int:
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    p = argparse.ArgumentParser(prog="run.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser(
        "sample",
        help="build the top-N GitHub-stars sample of JS/TS repos with package.json + lockfile",
    )
    ps.add_argument("--limit", type=int, default=100, help="number of repos to keep")
    ps.add_argument(
        "--refresh",
        action="store_true",
        help="discard the GitHub repo-probe cache before running",
    )
    ps.add_argument(
        "--min-npm-downloads",
        type=int,
        default=None,
        help="drop npm-published packages below this last-month download count "
        "(low-signal filter; unpublished repos are kept regardless)",
    )
    ps.set_defaults(func=cmd_sample)

    psm = sub.add_parser("smoke", help="single-project HEAD-only verification run")
    psm.set_defaults(func=cmd_smoke)

    def add_ignore_denylist(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--ignore-denylist",
            action="store_true",
            help=f"submit/re-drive rows even when data/{DENYLIST_FILENAME} marks "
            "their commit as unresolvable",
        )

    pu = sub.add_parser("submit", help="import projects and submit one HEAD analysis each")
    pu.add_argument("--limit", type=int, default=None, help="scan only the first N projects")
    pu.add_argument(
        "--snapshots",
        action="store_true",
        help="also analyze the historical quarterly snapshots (default: HEAD only)",
    )
    add_ignore_denylist(pu)
    pu.set_defaults(func=cmd_submit)

    pp = sub.add_parser(
        "poll",
        help="poll in-flight analyses, persist results, then auto-retry failures",
    )
    pp.add_argument(
        "--auto-retry",
        type=int,
        default=2,
        help="after convergence, re-drive retryable sad-terminal rows and poll "
        "again, up to N passes (default 2; 0 disables)",
    )
    add_ignore_denylist(pp)
    pp.set_defaults(func=cmd_poll)

    pr = sub.add_parser(
        "retry",
        help="re-submit sad-terminal manifest rows, replacing each row in place",
    )
    pr.add_argument(
        "--status",
        type=str,
        default=",".join(sorted(RETRYABLE_STATUSES)),
        help="comma-separated manifest statuses to re-drive",
    )
    pr.add_argument(
        "--date",
        type=str,
        default=None,
        help="only rows with this snapshot_date (e.g. 2024-01-01, or HEAD)",
    )
    pr.add_argument(
        "--project",
        type=str,
        default=None,
        help="only rows with this npm_name",
    )
    pr.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be resubmitted without submitting anything",
    )
    add_ignore_denylist(pr)
    pr.set_defaults(func=cmd_retry)

    pc = sub.add_parser("collect", help="build tidy Parquet tables from raw blobs")
    pc.add_argument(
        "--no-deps",
        action="store_true",
        help="skip the per-dependency table (keeps dep counts); avoids OOM on the longitudinal run",
    )
    pc.set_defaults(func=cmd_collect)

    pt = sub.add_parser(
        "triangulate",
        help="cross-check a stratified HEAD subsample against npm audit / "
        "osv-scanner and write per-project agreement stats",
    )
    pt.add_argument(
        "--n",
        type=int,
        default=20,
        help="target subsample size (stratified by vuln-load tercile x package manager)",
    )
    pt.add_argument(
        "--out",
        type=str,
        default=None,
        help="output parquet path (default data/tables/triangulation.parquet)",
    )
    pt.add_argument(
        "--dry-run",
        action="store_true",
        help="print the selected subsample and scanner availability without scanning",
    )
    pt.set_defaults(func=cmd_triangulate)

    pcl = sub.add_parser(
        "clean",
        help="bulk-delete the study org's projects/analyses (backlog clear) "
        "and/or sweep the downloader's on-disk clones",
    )
    pcl.add_argument(
        "--clones",
        action="store_true",
        help="also sweep the downloader's clone tree on disk (reclaims checkouts "
        "the backend never deletes)",
    )
    pcl.add_argument(
        "--clones-only",
        action="store_true",
        help="sweep the clone tree and skip the API-side project delete entirely "
        "— frees disk mid-run without destroying the backlog",
    )
    pcl.add_argument(
        "--ids",
        type=str,
        default=None,
        help="comma-separated project ids to delete (default: every project in the org)",
    )
    pcl.add_argument(
        "--limit",
        type=int,
        default=None,
        help="delete only the first N projects (ignored when --ids is given)",
    )
    pcl.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="ids per batch-delete request (API caps a single call at 500)",
    )
    pcl.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be deleted (projects and/or clones) without "
        "deleting anything",
    )
    pcl.set_defaults(func=cmd_clean)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
