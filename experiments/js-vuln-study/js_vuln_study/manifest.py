"""The manifest: the run's source of truth, one row per (git_url, snapshot_date).

Four states (`pending`, `done`, `failed`, `skipped`) plus a raw
`server_status` field that carries the API's exact status word (or, for a
row normalized from an older manifest, the legacy status word itself). The
`"*"` snapshot_date is a sentinel for project-wide skips recorded before any
snapshot was known (repo resolution or import failure).

`normalize_status` maps every status word this harness (or an older version
of it) has ever written onto one of the four states, so an archived manifest
from before this simplification reads identically through `read()`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path

STATES = {"pending", "done", "failed", "skipped"}

# Every status word the harness has written historically, mapped onto a state.
_LEGACY = {
    "submitted": "pending",
    "completed": "done",
    "success": "done",
    "failure": "failed",
    "failed": "failed",
    "cancelled": "failed",
    "failed-submit": "failed",
    "skipped": "skipped",
}


def normalize_status(status: str | None) -> str:
    """Map any manifest status word, old vocabulary or new, onto a state."""
    if status in STATES:
        return status
    return _LEGACY.get(status, "failed")


@dataclass
class Row:
    npm_name: str
    git_url: str
    snapshot_date: str  # "YYYY-MM-DD", "HEAD", or "*" (project-wide skip)
    state: str  # one of STATES
    tier: str = ""
    rank: int = 0
    branch: str | None = None
    commit_hash: str | None = None
    committed_at: str | None = None
    project_id: str | None = None
    analysis_id: str | None = None
    server_status: str | None = None
    error: str | None = None
    attempts: int = 0
    knowledge_asof: str | None = None
    run_id: str | None = None
    submitted_at: str | None = None
    terminal_at: str | None = None

    def key(self) -> tuple[str, str]:
        return (self.git_url, self.snapshot_date)


_FIELD_NAMES = {f.name for f in fields(Row)}


def _row_kwargs(rec: dict) -> dict:
    """Normalize one raw JSON manifest row (old or new vocabulary) into kwargs
    `Row(**...)` accepts."""
    if "state" in rec:
        kwargs = {k: v for k, v in rec.items() if k in _FIELD_NAMES}
    else:
        # A legacy row: has "status", not "state"/"attempts"/"run_id".
        kwargs = {k: v for k, v in rec.items() if k in _FIELD_NAMES}
        kwargs["state"] = normalize_status(rec.get("status"))
        kwargs.setdefault("server_status", rec.get("status"))
        kwargs.setdefault("attempts", 0)
        kwargs.setdefault("run_id", None)
    return kwargs


def read(path: Path) -> list[Row]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rows.append(Row(**_row_kwargs(json.loads(line))))
    return rows


def write_all(path: Path, rows: list[Row]) -> None:
    """Atomic whole-file rewrite (tmp + rename), so a Ctrl-C mid-write never
    corrupts the manifest."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(asdict(r)) + "\n")
    tmp.replace(path)


def append(path: Path, row: Row) -> None:
    """Append one new row (never used for a state transition: those go
    through `write_all` on the full row list, since a row already on disk is
    replaced in place, not duplicated)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(row)) + "\n")
