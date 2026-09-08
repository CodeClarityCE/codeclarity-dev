"""CLI entry point for the JS vulnerability-evolution study.

Four verbs, each taking a STUDY directory (e.g. `studies/top100`):

  sample: build a fresh top-N GitHub-stars sample (rarely needed: the
            canonical sample.json for an existing study is committed)
  run: provision -> submit missing analyses -> poll -> retry -> collect;
            resumable and idempotent, safe to interrupt and re-run
  analyze: collect (if needed) -> mine-lag -> results_numbers.json -> brief
  clean: batch-delete the study's projects (backlog clear) and archive
            its manifest so a later run re-imports fresh project ids
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is optional for CLI help
    def load_dotenv() -> None:  # type: ignore[misc]
        return None

from js_vuln_study import brief as brief_mod
from js_vuln_study import collect, miner, numbers, pipeline, sample as sample_mod
from js_vuln_study.client import CodeClarityClient
from js_vuln_study.config import Settings, Study

log = logging.getLogger("js_vuln_study.run")


def _client(settings: Settings) -> CodeClarityClient:
    return CodeClarityClient(settings.cc_base_url, settings.cc_email, settings.cc_password)


def cmd_sample(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    study = Study.load(Path(args.study))
    specs = sample_mod.build_sample(args.limit, settings.github_token, tier=study.name,
                                    output=study.sample_path)
    log.info("wrote %d rows to %s", len(specs), study.sample_path)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    study = Study.load(Path(args.study))
    with _client(settings) as client:
        pipeline.run(
            client, study, settings,
            limit=args.limit,
            refresh_head_flag=args.refresh_head,
            retry_target=args.retry,
            retry_force=args.force,
            dry_run=args.dry_run,
            give_up_hours=args.give_up_hours,
        )
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    study = Study.load(Path(args.study))
    baseline = Study.load(Path(args.baseline)) if args.baseline else None

    if not (study.tables_dir / "analyses.parquet").exists():
        collect.build_tables(study)

    if not args.no_mine:
        miner.run_mining(study, settings, limit=args.mine_limit)
        if baseline is not None and not (baseline.tables_dir / "remediation_events.parquet").exists():
            miner.run_mining(baseline, settings)

    numbers.build_numbers(study, baseline=baseline)
    pdf = brief_mod.build(study, baseline_study=baseline)
    log.info("wrote %s", pdf)
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    study = Study.load(Path(args.study))
    with _client(settings) as client:
        org_id, _, _ = pipeline.provision(client, study, settings)
        pipeline.clean(client, study, org_id, dry_run=args.dry_run)
    return 0


def main() -> int:
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="run.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sample", help="build a fresh top-N GitHub-stars sample")
    ps.add_argument("study", help="study directory, e.g. studies/top100")
    ps.add_argument("--limit", type=int, default=100)
    ps.set_defaults(func=cmd_sample)

    pr = sub.add_parser("run", help="provision, submit missing analyses, poll, retry, collect")
    pr.add_argument("study", help="study directory, e.g. studies/top100")
    pr.add_argument("--limit", type=int, default=None, help="submit only the first N projects")
    pr.add_argument("--refresh-head", action="store_true",
                     help="re-resolve and re-submit every HEAD row in place, then stop")
    pr.add_argument("--retry", metavar="SLUG[@DATE]", default=None,
                     help="re-drive one failed row (e.g. facebook/react or facebook/react@2024-01-01), then stop")
    pr.add_argument("--force", action="store_true",
                     help="with --retry, ignore the attempts cap and the CommitUnresolvable marker")
    pr.add_argument("--give-up-hours", type=int, default=pipeline.DEFAULT_GIVE_UP_HOURS,
                     help="client-side ceiling for a row stuck in updating_db or otherwise "
                          "non-terminal past the server reaper's window (default 30h)")
    pr.add_argument("--dry-run", action="store_true", help="print what would be submitted, write nothing")
    pr.set_defaults(func=cmd_run)

    pa = sub.add_parser("analyze", help="collect, mine fix commits, extract numbers, render the brief")
    pa.add_argument("study", help="study directory, e.g. studies/top100")
    pa.add_argument("--baseline", default=None, help="another study directory to compare against")
    pa.add_argument("--no-mine", action="store_true", help="skip the (resumable) fix-commit miner")
    pa.add_argument("--mine-limit", type=int, default=None, help="mine only the first N units")
    pa.set_defaults(func=cmd_analyze)

    pc = sub.add_parser("clean", help="batch-delete the study's projects and archive its manifest")
    pc.add_argument("study", help="study directory, e.g. studies/top100")
    pc.add_argument("--dry-run", action="store_true")
    pc.set_defaults(func=cmd_clean)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
