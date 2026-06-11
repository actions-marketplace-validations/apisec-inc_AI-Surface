"""Tests for --repo cloning helpers and the UI /api/scan scan path.

No network: we exercise URL validation, token handling, and local-path
scanning. Actual clones are not performed here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ai_surface import repo as repo_mod
from ai_surface.repo import RepoError, clone_repo_to_tmp
from ai_surface.ui_server import scan_for_request

FIXTURE = str(Path(__file__).parent / "fixtures" / "e2e_app")


def test_invalid_urls_are_rejected_without_network() -> None:
    for bad in [
        "",
        "ssh://git@github.com/o/r.git",
        "file:///etc/passwd",
        "https://github.com/o/r; rm -rf /",
        "https://github.com/o/../../../r",
        "ftp://example.com/r",
    ]:
        with pytest.raises(RepoError):
            clone_repo_to_tmp(bad)


def test_token_is_injected_into_clone_url() -> None:
    url = repo_mod._authed_url("https://github.com/org/repo", "ghp_secret")
    assert url == "https://x-access-token:ghp_secret@github.com/org/repo"
    # No token -> unchanged.
    assert repo_mod._authed_url("https://github.com/org/repo", None) == (
        "https://github.com/org/repo"
    )


def test_scan_for_request_scans_local_path() -> None:
    report = scan_for_request(path=FIXTURE)
    cats = {f.category for f in report.findings}
    assert "mcp-server" in cats and "api" in cats


def test_scan_for_request_bad_path_raises() -> None:
    with pytest.raises(FileNotFoundError):
        scan_for_request(path="/no/such/dir/ai-surface-test")
