"""Clone a remote git repo to a temp dir for scanning, then discard it.

Used by `ai-surface scan --repo <url>` and the local UI's /api/scan endpoint.

Privacy: the clone runs on the machine invoking ai-surface (your laptop or your
CI runner), the same place a local scan runs. Source is read locally and the
temp clone is always removed afterwards. A private-repo token is used only to
authenticate the clone subprocess; it is never stored, logged, or written to
any report.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

# Only https git URLs. No ssh, no file://, no shell metacharacters. We pass
# args as a list (never shell=True), so this is defense-in-depth, not the only
# guard. Keep the charset tight.
_URL_RE = re.compile(r"^https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$")


class RepoError(RuntimeError):
    """A clone could not be performed. Message is safe to show the user."""


def _validate_url(url: str) -> None:
    if not url or not _URL_RE.match(url):
        raise RepoError(
            "only https git URLs are supported (e.g. https://github.com/org/repo)"
        )
    if ".." in url:
        raise RepoError("invalid repository URL")


def _authed_url(url: str, token: str | None) -> str:
    """Inject a token for a private https clone. Returns url unchanged if no token."""
    if not token:
        return url
    return url.replace("https://", f"https://x-access-token:{token}@", 1)


def clone_repo_to_tmp(
    url: str,
    token: str | None = None,
    timeout: int = 180,
) -> tuple[Path, Callable[[], None]]:
    """Shallow-clone `url` into a temp dir. Returns (path, cleanup).

    The caller MUST call cleanup() when done (use clone_repo() for an
    auto-cleaning context manager). Raises RepoError on any failure.
    """
    _validate_url(url)
    tmp = Path(tempfile.mkdtemp(prefix="ai-surface-clone-"))

    def cleanup() -> None:
        shutil.rmtree(tmp, ignore_errors=True)

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", _authed_url(url, token), str(tmp)],
            check=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        cleanup()
        raise RepoError("git is not installed; --repo requires git on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        cleanup()
        raise RepoError(f"clone timed out after {timeout}s") from exc
    except subprocess.CalledProcessError as exc:
        cleanup()
        stderr = (exc.stderr or b"").decode("utf-8", "replace")
        if token:
            stderr = stderr.replace(token, "***")  # never echo the token
        raise RepoError(f"git clone failed: {stderr.strip()[:300]}") from exc

    return tmp, cleanup


@contextmanager
def clone_repo(url: str, token: str | None = None) -> Iterator[Path]:
    """Context manager: clone `url`, yield the local path, always clean up."""
    path, cleanup = clone_repo_to_tmp(url, token)
    try:
        yield path
    finally:
        cleanup()
