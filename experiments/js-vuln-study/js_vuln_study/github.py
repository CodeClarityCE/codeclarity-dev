"""Single GitHub HTTP surface: auth, rate-limit backoff, repo/commit lookups.

One client factory and one backoff policy, shared by `sample.py`, `pipeline.py`
and `miner.py` (previously duplicated three ways with two incompatible
rate-limit policies). The backoff sleeps until the primary limit's
`X-RateLimit-Reset` when it is exhausted, honours `Retry-After` when given,
and otherwise backs off exponentially. It never gives up early, so a
primary-limit hit degrades to a wait, not a silent skip.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

import httpx

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
GITHUB_API = "https://api.github.com"
RAW_GITHUB = "https://raw.githubusercontent.com"

# The four root-lockfile names js-sbom's PackageFileFinder.go accepts, used
# for sampling (RESULTS section 4's qualifying rule). The miner's
# `lockfiles.ROOT_LOCKFILES` (3 names, no npm-shrinkwrap.json) is a separate,
# deliberately narrower list (see that module's docstring).
LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")


def auth_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def make_client(base_url: str, token: str | None, timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=True,
        headers=auth_headers(token),
    )


def get(
    http: httpx.Client,
    path: str,
    params: dict[str, Any] | None = None,
    max_attempts: int = 4,
) -> httpx.Response:
    """GET with GitHub-aware backoff.

    200/404/409/422 return immediately (terminal: callers decide what they
    mean). 403/429 sleep until the primary limit resets, or `Retry-After`, or
    exponential backoff as a last resort) and retry, up to `max_attempts`.
    """
    r: httpx.Response | None = None
    for attempt in range(max_attempts):
        r = http.get(path, params=params)
        if r.status_code in (200, 404, 409, 422):
            return r
        if r.status_code in (403, 429):
            retry_after = r.headers.get("Retry-After")
            remaining = r.headers.get("X-RateLimit-Remaining")
            reset = r.headers.get("X-RateLimit-Reset")
            if retry_after:
                wait = float(retry_after)
            elif remaining == "0" and reset:
                wait = max(1.0, float(reset) - time.time() + 2.0)
            else:
                wait = 2.0 * (2**attempt)
            log.warning("github %d; sleeping %.1fs (%s)", r.status_code, wait, path)
            time.sleep(wait)
            continue
        return r
    return r  # type: ignore[return-value]


def get_repo(http: httpx.Client, owner: str, repo: str) -> dict[str, Any] | None:
    r = get(http, f"/repos/{owner}/{repo}")
    if r.status_code != 200:
        return None
    try:
        meta = r.json()
    except Exception:
        return None
    return meta if isinstance(meta, dict) else None


def root_files(http: httpx.Client, owner: str, repo: str, branch: str) -> set[str] | None:
    r = get(http, f"/repos/{owner}/{repo}/contents/", params={"ref": branch})
    if r.status_code != 200:
        return None
    try:
        entries = r.json()
    except Exception:
        return None
    if not isinstance(entries, list):
        return None
    return {e.get("name") for e in entries if isinstance(e, dict)}


def commit_before(
    http: httpx.Client,
    owner: str,
    repo: str,
    branch: str,
    until_iso: str | None,
) -> tuple[str, str] | None:
    """(sha, committed_at) for the latest commit on `branch` at/before
    `until_iso`, or the branch tip when `until_iso` is None."""
    params: dict[str, Any] = {"sha": branch, "per_page": 1}
    if until_iso is not None:
        params["until"] = until_iso
    r = get(http, f"/repos/{owner}/{repo}/commits", params=params)
    if r.status_code in (404, 409):
        return None
    r.raise_for_status()
    items = r.json()
    if not items:
        return None
    return items[0]["sha"], items[0]["commit"]["committer"]["date"]


def list_commits(
    http: httpx.Client, owner: str, repo: str, path: str, since: str, until: str
) -> list[dict]:
    """[{"sha","date"}] for commits touching `path` in (since, until], oldest
    first. Paginated; a gone/empty repo returns []."""
    out: list[dict] = []
    page = 1
    while True:
        r = get(
            http,
            f"/repos/{owner}/{repo}/commits",
            params={"path": path, "since": since, "until": until, "per_page": 100, "page": page},
        )
        if r.status_code in (404, 409):
            break
        r.raise_for_status()
        batch = r.json()
        out.extend({"sha": c["sha"], "date": c["commit"]["committer"]["date"]} for c in batch)
        if len(batch) < 100:
            break
        page += 1
    out.sort(key=lambda c: (c["date"], c["sha"]))
    return out


def fetch_raw(http_raw: httpx.Client, path: str) -> bytes | None:
    """Fetch raw file content at `path` (e.g. "/owner/repo/sha/file"). None on
    any non-200 (missing file, missing ref)."""
    r = http_raw.get(path)
    if r.status_code == 429:
        time.sleep(2.0)
        r = http_raw.get(path)
    if r.status_code != 200:
        return None
    return r.content


def parse_owner_repo(url: str) -> tuple[str, str] | None:
    """(owner, repo) from any GitHub-shaped clone/HTML URL, host-agnostic (so
    a sandbox mirror's own host still parses)."""
    slug = urlparse(url).path.strip("/")
    if not slug:
        return None
    owner, _, repo = slug.removesuffix(".git").partition("/")
    return (owner, repo) if owner and repo else None
