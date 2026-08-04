"""Captures what code and data actually produced a run's analyses.

`capture_run_meta` appends one JSON line to `data/run_meta.jsonl` per
submit/smoke invocation: the harness/API/backend commits, the analyzer's
*actual* plugin steps (read back from the API, not the versions we asked for),
the knowledge-DB freshness, and the config the run was submitted under.
collect.py copies the latest record next to the tables and warns when the
manifest mixes runs with diverging knowledge snapshots.

Every probe is best-effort: a missing git binary, an older API without
/knowledge/provenance, or an unreachable Postgres degrades to nulls with a
warning — provenance capture must never take a submit run down.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .client import CodeClarityClient, CodeClarityError
from .orchestrator import POLL_TIMEOUT, STARTED_TIMEOUT
from .snapshots import SNAPSHOT_DATES

log = logging.getLogger(__name__)

# …/experiments/js-vuln-study/js_vuln_study/provenance.py → repo root (same
# derivation as reclaim.clone_root). api/ and backend/ are submodules under it.
REPO_ROOT = Path(__file__).resolve().parents[3]

RUN_META_NAME = "run_meta.jsonl"


# ---- git / filesystem probes -------------------------------------------------


def _git(repo: Path, *args: str) -> str | None:
    """`git -C repo …` → stripped stdout, or None on any failure."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def _git_sha(repo: Path) -> str | None:
    return _git(repo, "rev-parse", "HEAD")


def _git_dirty(repo: Path) -> bool | None:
    out = _git(repo, "status", "--porcelain")
    return None if out is None else bool(out)


def _api_version() -> str | None:
    try:
        pkg = json.loads((REPO_ROOT / "api" / "package.json").read_text(encoding="utf-8"))
        return pkg.get("version")
    except (OSError, json.JSONDecodeError):
        return None


# ---- analyzer read-back --------------------------------------------------------


def _analyzer_steps(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
) -> list[list[dict[str, Any]]] | None:
    """The analyzer's actual [[{name, version}], …] stages, read back from the
    API — client.PLUGIN_VERSIONS only applies to *newly created* analyzers, so
    a pre-existing analyzer may run something else entirely."""
    name = os.environ.get("JS_VULN_ANALYZER_NAME", "js-vuln-study-v2")
    try:
        analyzer = client.get_analyzer_by_name(org_id, name)
    except CodeClarityError as e:
        log.warning("analyzer read-back failed: %s", e)
        return None
    if analyzer is None:
        log.warning("analyzer %r not found for read-back", name)
        return None
    if analyzer.get("id") != analyzer_id:
        # Stale setup.json cache or a renamed analyzer — record the read-back
        # anyway, but make the mismatch visible.
        log.warning(
            "analyzer %r resolved to id %s but the run uses %s",
            name, analyzer.get("id"), analyzer_id,
        )
    return [
        [{"name": s.get("name"), "version": s.get("version")} for s in (stage or [])]
        for stage in (analyzer.get("steps") or [])
    ]


# ---- knowledge-DB freshness ----------------------------------------------------


def _knowledge_via_api(client: CodeClarityClient) -> dict[str, Any] | None:
    try:
        return client.get_knowledge_provenance()
    except CodeClarityError as e:
        log.warning(
            "GET /knowledge/provenance failed (%s) — older API? trying Postgres directly", e,
        )
        return None


def _knowledge_via_postgres() -> dict[str, Any] | None:
    """Direct-Postgres fallback (PG_DB_* env). In dev the DB port is published
    on the host only, so this is expected to fail from inside a container."""
    import pg8000.dbapi  # deferred: only needed on the fallback path

    host = os.environ.get("PG_DB_HOST", "127.0.0.1")
    port = int(os.environ.get("PG_DB_PORT", "5432"))
    user = os.environ.get("PG_DB_USER", "postgres")
    password = os.environ.get("PG_DB_PASSWORD", "!ChangeMe!")

    def one_row(database: str, sql: str) -> tuple | None:
        conn = pg8000.dbapi.connect(
            user=user, password=password, host=host, port=port,
            database=database, timeout=10,
        )
        try:
            cur = conn.cursor()
            cur.execute(sql)
            return cur.fetchone()
        finally:
            conn.close()

    def iso(v: Any) -> Any:
        return v.isoformat() if hasattr(v, "isoformat") else (v or None)

    try:
        cfg = one_row(
            "config", "SELECT nvd_last, npm_last, gcve_last, osv_last FROM config LIMIT 1"
        )
        epss = one_row("knowledge", "SELECT count(*) FROM epss")
    except Exception as e:  # noqa: BLE001 — any driver/network error means "unknown"
        log.warning("direct Postgres provenance failed: %s", e)
        return None
    nvd_last, npm_last, gcve_last, osv_last = cfg if cfg else (None, None, None, None)
    return {
        "knowledge_sources": {
            "nvd": iso(nvd_last),
            "npm": iso(npm_last),
            "gcve": iso(gcve_last),
            "osv": iso(osv_last),
        },
        "epss_rows": epss[0] if epss else None,
    }


# ---- entry point ----------------------------------------------------------------


def capture_run_meta(
    client: CodeClarityClient,
    org_id: str,
    analyzer_id: str,
    data_dir: Path,
    extra: dict | None = None,
) -> dict:
    """Append one provenance record to data/run_meta.jsonl and return it."""
    knowledge = _knowledge_via_api(client) or _knowledge_via_postgres()
    if knowledge is None:
        log.warning("knowledge provenance unavailable (API and Postgres); recording nulls")
        knowledge = {"knowledge_sources": None, "epss_rows": None}

    meta: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "run_id": str(uuid.uuid4()),
        "experiment_sha": _git_sha(REPO_ROOT),
        "experiment_dirty": _git_dirty(REPO_ROOT),
        "api_sha": _git_sha(REPO_ROOT / "api"),
        "backend_sha": _git_sha(REPO_ROOT / "backend"),
        "api_version": _api_version(),
        "org_id": org_id,
        "analyzer_id": analyzer_id,
        "analyzer_steps": _analyzer_steps(client, org_id, analyzer_id),
        "knowledge": knowledge,
        "config": {
            "snapshot_dates": list(SNAPSHOT_DATES),
            "poll_timeout": POLL_TIMEOUT,
            "started_timeout": STARTED_TIMEOUT,
        },
    }
    if extra:
        meta.update(extra)

    path = data_dir / RUN_META_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(meta) + "\n")
    log.info("run meta recorded (run_id=%s) to %s", meta["run_id"], path)
    return meta
