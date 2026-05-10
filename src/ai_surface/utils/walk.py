"""gitignore-aware file walker.

All detectors should walk the file tree through `walk_files()` so they
respect .gitignore by default and behave consistently.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, List, Optional

import pathspec


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


def _load_gitignore(root: Path) -> Optional[pathspec.PathSpec]:
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
    extensions: Optional[List[str]] = None,
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
    ext_filter: Optional[set] = None
    if extensions:
        ext_filter = {("." + e.lstrip(".")).lower() for e in extensions}

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
            full = Path(dirpath) / fname
            if ext_filter is not None and full.suffix.lower() not in ext_filter:
                continue
            if gitignore is not None:
                rel = full.relative_to(root_path).as_posix()
                if gitignore.match_file(rel):
                    continue
            yield full


def relative_to_root(path: Path, root: str) -> str:
    """Render `path` as a posix-style relative string from `root`. For evidence display."""
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        # Path is outside root somehow; return absolute
        return path.as_posix()


def read_text_safe(path: Path, max_bytes: int = 5_000_000) -> str:
    """Read a text file safely. Returns empty string on error or if file is too large.

    max_bytes: cap to avoid loading multi-GB files. 5MB default is generous for source code.
    """
    try:
        if path.stat().st_size > max_bytes:
            return ""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return ""
