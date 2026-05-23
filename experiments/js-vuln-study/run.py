"""CLI entry point for the JS vulnerability-evolution experiment.

Subcommands:
  sample    — build the popularity-stratified project list
  smoke     — run a single-project HEAD-only scan (verification gate)
  submit    — import every project in the sample and submit all analyses
  poll      — poll all in-flight analyses and persist their results
  collect   — flatten raw blobs into Parquet tables
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

from js_vuln_study.client import CodeClarityClient
from js_vuln_study.collect import build_tables
from js_vuln_study.orchestrator import (
    import_and_schedule,
    poll_and_collect,
)
from js_vuln_study.sample import ProjectSpec, build_sample, load_sample

DATA_DIR = Path(__file__).resolve().parent / "data"
SAMPLE_PATH = DATA_DIR / "sample.json"
SETUP_CACHE = DATA_DIR / "setup.json"
AGGREGATE_CACHE = DATA_DIR / "npm_aggregate.json"
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
    successful setup and reuse them on later runs.
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
        name="js-vuln-study-2026",
        description="Popularity-stratified study of JS vulnerability evolution.",
    )
    analyzer_id = client.ensure_js_analyzer(org_id)
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
        for p in (AGGREGATE_CACHE, PROBE_CACHE):
            p.unlink(missing_ok=True)
    build_sample(
        per_tier=args.per_tier,
        seed=args.seed,
        max_rank=args.max_rank,
        output=SAMPLE_PATH,
        require_lockfile=not args.no_lockfile_filter,
        aggregate_cache=AGGREGATE_CACHE,
        probe_cache=PROBE_CACHE,
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
            integration_id=integration_id, skip_head_only=args.head_only,
        )
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    with _client() as client:
        org_id, _, _ = _ensure_setup(client)
        poll_and_collect(client, org_id, DATA_DIR)
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    build_tables(DATA_DIR)
    return 0


def main() -> int:
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    p = argparse.ArgumentParser(prog="run.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sample", help="build the popularity-stratified sample")
    ps.add_argument("--per-tier", type=int, default=100)
    ps.add_argument("--seed", type=int, default=42)
    ps.add_argument("--max-rank", type=int, default=20_000)
    ps.add_argument(
        "--no-lockfile-filter",
        action="store_true",
        help="do NOT drop repos without a committed lockfile (faster but produces empty scans)",
    )
    ps.add_argument(
        "--refresh",
        action="store_true",
        help="discard the npm-search and GitHub-probe caches before running",
    )
    ps.set_defaults(func=cmd_sample)

    psm = sub.add_parser("smoke", help="single-project HEAD-only verification run")
    psm.set_defaults(func=cmd_smoke)

    pu = sub.add_parser("submit", help="import projects and submit all analyses")
    pu.add_argument("--limit", type=int, default=None, help="scan only the first N projects")
    pu.add_argument("--head-only", action="store_true", help="skip historical snapshots")
    pu.set_defaults(func=cmd_submit)

    pp = sub.add_parser("poll", help="poll in-flight analyses and persist results")
    pp.set_defaults(func=cmd_poll)

    pc = sub.add_parser("collect", help="build tidy Parquet tables from raw blobs")
    pc.set_defaults(func=cmd_collect)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
