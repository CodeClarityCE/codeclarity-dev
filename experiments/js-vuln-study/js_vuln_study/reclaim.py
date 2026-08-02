"""Reclaims the downloader's on-disk clones once their analysis is finished.

The CodeClarity downloader clones every analysed snapshot to

    {DOWNLOAD_PATH}/{org_id}/projects/{project_id}/{commit_hash | branch}

(bind-mounted as `/private` into the downloader and plugin containers; see
backend/services/downloader/git.go:86-95). Nothing in the backend ever deletes
those trees — only an API-side *project* delete does — so a longitudinal run
accumulates one ~10 MB checkout per (project, snapshot) and eventually fills the
disk.

Analysis results do not depend on the checkout: plugin output is persisted as a
jsonb row in Postgres and read back over the API, and only the SBOM stage ever
touches DOWNLOAD_PATH. So once an analysis is terminal its clone is dead weight.
Re-submitting an analysis re-clones, so deleting is safe there too — the tree is
a per-analysis input, never a cache.

This module is deliberately ignorant of the manifest schema and the API client:
it takes plain strings and Paths, which keeps it unit-testable and keeps the
path-safety rules in one place.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)

# Where the downloader's clones land on this host. Defaults to <repo-root>/private,
# which is correct inside the devcontainer (the compose bind mount resolves to the
# same directory the harness sees). JS_VULN_* matches the prefix already used for
# the poll timeouts; CC_* is reserved here for API-connection settings.
CLONE_DIR_ENV = "JS_VULN_CLONE_DIR"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# A leaf is either a commit SHA or a plain branch name. Branch names containing
# '/' (release/1.x) are written by the downloader as nested directories; the
# harness only ever uses default branches or SHAs, so those are refused rather
# than modelled.
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,254}$")

_UNSET = object()
_root_cache: object = _UNSET
_warned_missing = False


# ---- clone root ------------------------------------------------------------


def clone_root() -> Path | None:
    """The clone tree's root, or None when it isn't visible from here.

    Returning None (rather than raising) is the whole contract of this module:
    the harness may legitimately run outside the devcontainer, and reclamation
    is an optimisation that must never take the poll loop down with it. The
    not-found warning is emitted at most once per process.
    """
    global _root_cache, _warned_missing
    if _root_cache is not _UNSET:
        return _root_cache  # type: ignore[return-value]

    override = os.environ.get(CLONE_DIR_ENV)
    if override:
        root = Path(override).expanduser()
    else:
        # …/experiments/js-vuln-study/js_vuln_study/reclaim.py → repo root
        repo_root = Path(__file__).resolve().parents[3]
        # Sanity-check we really landed on the repo, so a relocated harness
        # doesn't point at some unrelated `private` directory.
        root = repo_root / "private" if (repo_root / "backend").is_dir() else Path("")

    resolved: Path | None
    try:
        resolved = root.resolve() if str(root) else None
        if resolved is not None and not resolved.is_dir():
            resolved = None
    except OSError:
        resolved = None

    if resolved is None and not _warned_missing:
        _warned_missing = True
        log.warning(
            "clone reclamation disabled: %s not found (set %s to the downloader's "
            "DOWNLOAD_PATH bind mount)",
            root or "<repo-root>/private",
            CLONE_DIR_ENV,
        )

    _root_cache = resolved
    return resolved


def reset_cache() -> None:
    """Forget the memoised root. For tests that manipulate the env var."""
    global _root_cache, _warned_missing
    _root_cache = _UNSET
    _warned_missing = False


def leaf_for(commit_hash: str | None, branch: str | None) -> str | None:
    """The directory leaf the downloader used for this analysis.

    Mirrors client.py's `path_leaf = commit_hash if commit_hash else branch`
    (and thus downloader git.go:91-95). Kept here so the two can be tested
    against each other.
    """
    leaf = (commit_hash or "").strip() or (branch or "").strip()
    return leaf or None


# ---- path safety -----------------------------------------------------------


def _safe_join(base: Path, *segments: str) -> Path:
    """Join segments under `base`, refusing anything that escapes it.

    The Python counterpart of the API's validateAndJoinPath
    (api/src/utils/path-validator.ts): each segment is reduced to its basename,
    which strips '..', separators and '~', then the result is resolved (which
    also collapses symlinks) and checked to still live under `base`.
    """
    root = base.resolve()
    out = root
    for seg in segments:
        if not isinstance(seg, str) or not seg:
            raise ValueError(f"invalid path segment: {seg!r}")
        cleaned = PurePosixPath(seg.replace("\0", "")).name
        if not cleaned or cleaned in (".", ".."):
            raise ValueError(f"path segment empty after sanitisation: {seg!r}")
        out = out / cleaned
    resolved = out.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"path traversal detected: {resolved} outside {root}")
    return resolved


def is_uuid(value: str | None) -> bool:
    return bool(value) and bool(_UUID_RE.match(value))  # type: ignore[arg-type]


def is_leaf_shaped(value: str | None) -> bool:
    """True when `value` looks like something the downloader would have created."""
    if not value or value in (".", "..") or ".." in value:
        return False
    return bool(_COMMIT_RE.match(value) or _BRANCH_RE.match(value))


# ---- sizing and deletion ---------------------------------------------------


def dir_size(path: Path) -> int:
    """Total size of the regular files under `path`. Unreadable entries skipped."""
    total = 0
    try:
        for entry in path.rglob("*"):
            try:
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            except OSError:
                continue
    except OSError:
        return total
    return total


def _on_rmtree_error(func, path, exc) -> None:  # noqa: ANN001 - shutil callback
    # Swallow, but never silently: `ignore_errors=True` is exactly how "the disk
    # still fills up" goes unnoticed.
    log.warning("could not remove %s: %s", path, exc)


def _rmtree(path: Path) -> None:
    shutil.rmtree(path, onexc=_on_rmtree_error)


def _delete_dir(path: Path, *, dry_run: bool) -> int:
    """Delete `path` and return the bytes it held (0 if absent or refused)."""
    if not path.is_dir() or path.is_symlink():
        return 0
    size = dir_size(path)
    if dry_run:
        return size
    _rmtree(path)
    if path.exists():
        log.warning("clone directory survived removal: %s", path)
        return 0
    return size


def _prune_empty_parents(leaf_parent: Path, root: Path) -> None:
    """rmdir empty {project}/, projects/ and {org}/ directories above a leaf.

    rmdir (never rmtree) so a race with a concurrent clone can't take out a live
    tree — a non-empty directory just fails harmlessly.
    """
    current = leaf_parent
    while current != root and root in current.parents:
        try:
            current.rmdir()
        except OSError:
            return  # not empty, or gone — stop climbing
        current = current.parent


def reclaim_leaf(
    org_id: str,
    project_id: str,
    leaf: str,
    *,
    dry_run: bool = False,
    prune: bool = True,
) -> int:
    """Delete one analysis's clone directory. Returns bytes freed.

    Returns 0 — quietly — when reclamation is disabled, the shape is wrong, or
    the directory is already gone. The already-gone case is normal (analyses
    that never got past the queue), so it must not warn.
    """
    root = clone_root()
    if root is None:
        return 0
    if not (is_uuid(org_id) and is_uuid(project_id) and is_leaf_shaped(leaf)):
        log.debug("refusing to reclaim oddly-shaped path %s/%s/%s", org_id, project_id, leaf)
        return 0
    try:
        path = _safe_join(root, org_id, "projects", project_id, leaf)
    except ValueError as e:
        log.warning("refusing to reclaim %s/%s/%s: %s", org_id, project_id, leaf, e)
        return 0

    if not path.is_dir():
        log.debug("no clone to reclaim at %s", path)
        return 0

    freed = _delete_dir(path, dry_run=dry_run)
    if freed and prune and not dry_run:
        _prune_empty_parents(path.parent, root)
    return freed


# ---- orphan sweep ----------------------------------------------------------


@dataclass
class SweepReport:
    scanned: int = 0
    deleted: list[tuple[Path, int]] = field(default_factory=list)
    kept: list[tuple[Path, str]] = field(default_factory=list)
    bytes_freed: int = 0

    def kept_by_reason(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for _, reason in self.kept:
            out[reason] = out.get(reason, 0) + 1
        return out


def sweep(
    org_id: str,
    keep: set[tuple[str, str]],
    *,
    dry_run: bool = False,
) -> SweepReport:
    """Delete every clone under `org_id` whose (project_id, leaf) isn't in `keep`.

    Scoped to a single org on purpose: other org directories in the clone root
    belong to other work in this devcontainer and are never touched.
    """
    rep = SweepReport()
    root = clone_root()
    if root is None or not is_uuid(org_id):
        return rep
    try:
        projects_dir = _safe_join(root, org_id, "projects")
    except ValueError as e:
        log.warning("refusing to sweep org %s: %s", org_id, e)
        return rep
    if not projects_dir.is_dir():
        return rep

    for project_dir in sorted(projects_dir.iterdir()):
        if not project_dir.is_dir() or project_dir.is_symlink():
            continue  # tolerate stray files like .DS_Store
        project_id = project_dir.name
        if not is_uuid(project_id):
            rep.scanned += 1
            rep.kept.append((project_dir, "shape-rejected"))
            continue

        for leaf_dir in sorted(project_dir.iterdir()):
            if not leaf_dir.is_dir() or leaf_dir.is_symlink():
                continue
            rep.scanned += 1
            leaf = leaf_dir.name
            if not is_leaf_shaped(leaf):
                rep.kept.append((leaf_dir, "shape-rejected"))
                continue
            if (project_id, leaf) in keep:
                rep.kept.append((leaf_dir, "in-use"))
                continue
            freed = _delete_dir(leaf_dir, dry_run=dry_run)
            rep.deleted.append((leaf_dir, freed))
            rep.bytes_freed += freed
            log.debug("reclaimed %s (%.1f MB)", leaf_dir, freed / 1e6)

        if not dry_run:
            _prune_empty_parents(project_dir, root)

    if not dry_run:
        _prune_empty_parents(projects_dir, root)
    return rep
