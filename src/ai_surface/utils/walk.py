"""File walker that respects the scan-root ``.gitignore``.

All detectors should walk the file tree through ``walk_files()`` so they
share a single, consistent traversal policy.

Scope of gitignore support (intentionally narrow):

* Reads ``.gitignore`` at the scan root only. Nested per-directory
  ``.gitignore`` files inside the tree are NOT honoured.
* Does NOT consult ``.git/info/exclude``, the global git excludesfile,
  or skip-worktree / assume-unchanged state.
* Always-skip directories in ``ALWAYS_SKIP_DIRS`` are pruned regardless
  of gitignore content.
"""
from __future__ import annotations

import logging
import os
import stat as _stat
from collections.abc import Iterator
from pathlib import Path

import pathspec

log = logging.getLogger(__name__)

# Safety caps for traversal. Hostile or pathological trees (huge monorepos,
# generated artifacts that escaped ALWAYS_SKIP_DIRS, symlink loops) must not
# stall the scanner or balloon memory. These caps short-circuit traversal
# once exceeded; a warning is logged so the user knows the inventory is
# truncated rather than silently incomplete.
MAX_FILES = 250_000
MAX_TOTAL_BYTES = 5 * 1024 * 1024 * 1024  # 5 GiB cumulative file size scanned

# Directories we always skip even if not in .gitignore. Saves time on large repos.
ALWAYS_SKIP_DIRS = frozenset(
    [
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "target",  # rust/java build dir
        ".next",
        ".nuxt",
        ".cache",
        ".parcel-cache",
        ".turbo",
    ]
)

# Files we always skip because they are ai-surface's own output artifacts.
# Without this, re-scanning a repo that ran --update-baseline or
# --write-inventory turns the saved report file into a fresh finding (the
# baseline JSON contains literal strings like HELICONE_API_KEY in its
# captured metadata, which the source-level gateway detector then matches).
ALWAYS_SKIP_FILES = frozenset(
    [
        ".ai-surface-baseline.json",
        ".ai-inventory.md",
    ]
)


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    """Load .gitignore at root if present. Returns None if no gitignore."""
    gitignore_path = root / ".gitignore"
    if not gitignore_path.is_file():
        return None
    try:
        with gitignore_path.open("r", encoding="utf-8", errors="replace") as f:
            return pathspec.PathSpec.from_lines("gitwildmatch", f)
    except OSError:
        return None


def walk_files(
    root: str,
    extensions: list[str] | None = None,
    follow_symlinks: bool = False,
) -> Iterator[Path]:
    """Yield file paths under `root`, respecting .gitignore and ALWAYS_SKIP_DIRS.

    Args:
        root: directory to walk (string or Path-like).
        extensions: optional list of file extensions to filter (with or without dot).
                    Example: [".py", "py", ".ts"]. None = all files.
        follow_symlinks: whether to follow symlinks. Default False for safety.

    Yields:
        Path objects (absolute) for each matching file.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return

    gitignore = _load_gitignore(root_path)

    # Normalize extensions: ensure leading dot, lowercase
    ext_filter: set | None = None
    if extensions:
        ext_filter = {("." + e.lstrip(".")).lower() for e in extensions}

    files_yielded = 0
    cumulative_bytes = 0
    caps_warned = False

    for dirpath, dirnames, filenames in os.walk(root_path, followlinks=follow_symlinks):
        # In-place filter dirnames so os.walk skips them entirely
        dirnames[:] = [d for d in dirnames if d not in ALWAYS_SKIP_DIRS]

        # Apply gitignore to remaining dirs
        if gitignore is not None:
            kept = []
            for d in dirnames:
                rel = os.path.relpath(os.path.join(dirpath, d), root_path)
                # gitignore uses forward slashes, with a trailing slash for dirs
                rel_norm = rel.replace(os.sep, "/") + "/"
                if not gitignore.match_file(rel_norm):
                    kept.append(d)
            dirnames[:] = kept

        for fname in filenames:
            if fname in ALWAYS_SKIP_FILES:
                continue
            full = Path(dirpath) / fname
            if ext_filter is not None and full.suffix.lower() not in ext_filter:
                continue
            if gitignore is not None:
                rel = full.relative_to(root_path).as_posix()
                if gitignore.match_file(rel):
                    continue
            # Use lstat() so we never follow a symlink during size accounting.
            # This prevents a symlink pointing at /dev/zero or a 100GiB blob
            # outside the tree from being counted as if it lived inline.
            try:
                st = os.lstat(full)
            except OSError:
                continue
            cumulative_bytes += st.st_size
            files_yielded += 1
            if files_yielded > MAX_FILES or cumulative_bytes > MAX_TOTAL_BYTES:
                if not caps_warned:
                    log.warning(
                        "walk_files hit resource cap (files=%d, bytes=%d). "
                        "Truncating traversal; inventory may be incomplete.",
                        files_yielded,
                        cumulative_bytes,
                    )
                    caps_warned = True
                return
            yield full


def relative_to_root(path: Path, root: str) -> str:
    """Render ``path`` as a posix-style relative string from ``root`` for evidence display.

    Safety: if ``path`` cannot be expressed relative to ``root`` (e.g., a
    symlink target outside the tree, or a synthetic path passed in from a
    test fixture), we DO NOT fall back to the absolute path. Doing so would
    leak the user's local filesystem layout (home directory, internal mount
    points, employer names) into JSON / markdown reports that frequently end
    up committed to git, posted as PR comments, or pasted into public
    issues. Instead, we return just the file's basename, prefixed with
    ``<outside-root>/`` so the report makes it visible that a path was
    redacted rather than silently truncated.
    """
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return f"<outside-root>/{path.name}"


def read_text_safe(path: Path, max_bytes: int = 5_000_000) -> str:
    """Read a text file safely. Returns empty string on error or if file is too large.

    max_bytes: cap to avoid loading multi-GB files. 5MB default is generous for source code.

    Security notes:
      * We refuse to follow symlinks. ``os.lstat`` is used for the initial
        size check so a symlink to e.g. ``/dev/zero`` or a multi-GB file
        outside the scanned tree can't be smuggled past the cap.
      * Reads are bounded by ``max_bytes`` even after the lstat check, as a
        defence-in-depth measure against TOCTOU races between the stat and
        the open.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return ""
    # Reject symlinks outright. Detectors operate on real files in the tree.
    if _stat.S_ISLNK(st.st_mode):
        return ""
    if st.st_size > max_bytes:
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            # Cap the read explicitly. Even if a TOCTOU race grew the file
            # after the lstat above, we never read past max_bytes.
            return f.read(max_bytes)
    except (OSError, UnicodeDecodeError):
        return ""
