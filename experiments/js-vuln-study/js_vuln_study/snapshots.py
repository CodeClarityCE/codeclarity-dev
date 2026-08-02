"""Resolve commit hashes at target historical dates.

Primary source: GitHub's REST API (`GET /repos/{owner}/{repo}/commits`) with
the `until` parameter. Without a token the rate limit is 60 req/h; with one
(via `GITHUB_TOKEN`) it is 5000 req/h, which is more than enough for the 400
project × 7 date grid the study needs.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

import httpx

log = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# Quarterly 2022-Q1 .. 2026-Q2 — a pre-LLM baseline (2022) through today, to
# chart vulnerability evolution. Repos that don't yet exist at a date are skipped
# (commit_before returns None). HEAD (commit_hash = None) is appended last.
SNAPSHOT_DATES = [
    "2022-01-01", "2022-04-01", "2022-07-01", "2022-10-01",
    "2023-01-01", "2023-04-01", "2023-07-01", "2023-10-01",
    "2024-01-01", "2024-04-01", "2024-07-01", "2024-10-01",
    "2025-01-01", "2025-04-01", "2025-07-01", "2025-10-01",
    "2026-01-01", "2026-04-01",
]


@dataclass
class Snapshot:
    date: str  # "YYYY-MM-DD" or "HEAD"
    commit_hash: str | None  # None means "use HEAD on default branch"
    committed_at: str | None  # ISO string, when available


def _auth_headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _handle_rate_limit(resp: httpx.Response) -> None:
    """Block until GitHub's rate-limit window re-opens if we're throttled."""
    if resp.status_code != 403 and resp.status_code != 429:
        return
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset:
        wait = max(1, int(reset) - int(time.time()) + 5)
        log.warning("github rate limited, sleeping %ss", wait)
        time.sleep(wait)


def get_default_branch(http: httpx.Client, owner: str, repo: str) -> str | None:
    r = http.get(f"/repos/{owner}/{repo}", headers=_auth_headers())
    if r.status_code == 404:
        return None
    _handle_rate_limit(r)
    r.raise_for_status()
    return r.json().get("default_branch")


def commit_before(
    http: httpx.Client,
    owner: str,
    repo: str,
    until_iso: str | None,
    branch: str,
) -> tuple[str, str] | None:
    """Return (sha, committed_at) for the latest commit on `branch` at or before
    `until_iso` — or the branch tip when `until_iso` is None."""
    params: dict[str, str | int] = {"sha": branch, "per_page": 1}
    if until_iso is not None:
        params["until"] = until_iso
    r = http.get(
        f"/repos/{owner}/{repo}/commits",
        params=params,
        headers=_auth_headers(),
    )
    if r.status_code == 409:
        # empty repository
        return None
    if r.status_code == 404:
        return None
    _handle_rate_limit(r)
    r.raise_for_status()
    items = r.json()
    if not items:
        return None
    sha = items[0]["sha"]
    committed_at = items[0]["commit"]["committer"]["date"]
    return sha, committed_at


def resolve_head(owner: str, repo: str, branch: str) -> tuple[str, str] | None:
    """Resolve the current tip of `branch` to (sha, committed_at).

    Used to pin HEAD analyses to a concrete commit at submit time: a branch-only
    analysis is unreproducible (the downloader clones whatever the tip is when
    the queue drains), and the manifest would carry no commit for the row.
    """
    with httpx.Client(base_url=GITHUB_API, timeout=30.0) as http:
        return commit_before(http, owner, repo, None, branch)


def resolve_snapshots(
    owner: str,
    repo: str,
    dates: Iterable[str] = SNAPSHOT_DATES,
    include_head: bool = True,
) -> tuple[str | None, list[Snapshot]]:
    """Return (default_branch, snapshots) for a given GitHub repo.

    The returned list contains one `Snapshot` per requested date (+ HEAD),
    minus dates that predate the repository.
    """
    with httpx.Client(base_url=GITHUB_API, timeout=30.0) as http:
        branch = get_default_branch(http, owner, repo)
        if branch is None:
            return None, []

        out: list[Snapshot] = []
        for d in dates:
            iso = datetime.fromisoformat(d).replace(tzinfo=timezone.utc).isoformat()
            result = commit_before(http, owner, repo, iso, branch)
            if result is None:
                continue
            sha, committed_at = result
            out.append(Snapshot(date=d, commit_hash=sha, committed_at=committed_at))

        if include_head:
            out.append(Snapshot(date="HEAD", commit_hash=None, committed_at=None))

        return branch, out
