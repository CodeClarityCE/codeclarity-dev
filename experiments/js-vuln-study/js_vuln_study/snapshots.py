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

# 2024-Q4 .. 2026-Q1, spaced roughly quarterly. HEAD is the last entry and has
# commit_hash = None (meaning "default branch HEAD").
SNAPSHOT_DATES = [
    "2024-10-01",
    "2025-01-01",
    "2025-04-01",
    "2025-07-01",
    "2025-10-01",
    "2026-01-01",
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
    until_iso: str,
    branch: str,
) -> tuple[str, str] | None:
    """Return (sha, committed_at) for the latest commit on `branch` at or before `until_iso`."""
    r = http.get(
        f"/repos/{owner}/{repo}/commits",
        params={"sha": branch, "until": until_iso, "per_page": 1},
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
