"""Tests for the gitignore-aware file walker."""
from __future__ import annotations

import os
from pathlib import Path

from ai_surface.utils.walk import read_text_safe, relative_to_root, walk_files


def _make(tmp: Path, rel: str, content: str = "x") -> Path:
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_walk_yields_files(tmp_path: Path) -> None:
    _make(tmp_path, "a.py")
    _make(tmp_path, "b/c.py")
    _make(tmp_path, "b/d.txt")
    out = sorted(p.name for p in walk_files(str(tmp_path)))
    assert out == ["a.py", "c.py", "d.txt"]


def test_walk_filters_by_extension(tmp_path: Path) -> None:
    _make(tmp_path, "a.py")
    _make(tmp_path, "b.txt")
    _make(tmp_path, "c.PY")
    out = sorted(p.name for p in walk_files(str(tmp_path), extensions=[".py"]))
    # Case-insensitive match expected
    assert "a.py" in out
    assert "c.PY" in out
    assert "b.txt" not in out


def test_walk_skips_always_skip_dirs(tmp_path: Path) -> None:
    _make(tmp_path, "src/a.py")
    _make(tmp_path, "node_modules/foo.js")
    _make(tmp_path, ".git/HEAD")
    _make(tmp_path, "__pycache__/x.pyc")
    out = [p.name for p in walk_files(str(tmp_path))]
    assert "a.py" in out
    assert "foo.js" not in out
    assert "HEAD" not in out
    assert "x.pyc" not in out


def test_walk_respects_gitignore(tmp_path: Path) -> None:
    _make(tmp_path, ".gitignore", "secrets/\n*.log\n")
    _make(tmp_path, "secrets/api.txt")
    _make(tmp_path, "app.log")
    _make(tmp_path, "main.py")
    out = sorted(p.name for p in walk_files(str(tmp_path)))
    assert "main.py" in out
    assert ".gitignore" in out
    assert "api.txt" not in out
    assert "app.log" not in out


def test_read_text_safe_returns_empty_on_missing(tmp_path: Path) -> None:
    assert read_text_safe(tmp_path / "nope.txt") == ""


def test_read_text_safe_caps_size(tmp_path: Path) -> None:
    big = _make(tmp_path, "big.txt", "x" * 10)
    assert read_text_safe(big, max_bytes=5) == ""
    assert read_text_safe(big, max_bytes=100) == "x" * 10


def test_read_text_safe_refuses_symlink(tmp_path: Path) -> None:
    target = _make(tmp_path, "target.txt", "real")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        # Skip on filesystems / platforms that disallow symlink creation.
        return
    assert read_text_safe(link) == ""


def test_relative_to_root_outside_does_not_leak_absolute_path(tmp_path: Path) -> None:
    # A path that lives outside the scan root must not surface as an
    # absolute filesystem path in evidence — that leaks the user's
    # home directory / employer layout into reports.
    outside = Path("/etc/hostname")
    rel = relative_to_root(outside, str(tmp_path))
    assert not rel.startswith("/")
    assert "<outside-root>" in rel
    assert rel.endswith("hostname")


def test_is_test_path_directory_segments() -> None:
    from ai_surface.utils.walk import is_test_path
    assert is_test_path("tests/foo.py")
    assert is_test_path("backend/tests/unit/llm.py")
    assert is_test_path("src/__tests__/agent.ts")
    assert is_test_path("e2e/flow.ts")
    assert is_test_path("pkg/spec/thing.py")


def test_is_test_path_filename_shapes() -> None:
    from ai_surface.utils.walk import is_test_path
    assert is_test_path("test_app.py")
    assert is_test_path("app_test.py")
    assert is_test_path("conftest.py")
    assert is_test_path("handlers_test.go")
    assert is_test_path("agent.spec.ts")
    assert is_test_path("agent.test.tsx")


def test_is_test_path_negatives() -> None:
    from ai_surface.utils.walk import is_test_path
    # Production code, examples, and demos are not tests.
    assert not is_test_path("app.py")
    assert not is_test_path("src/agents/support.py")
    assert not is_test_path("examples/quickstart/agent.py")
    assert not is_test_path("contest.py")          # not conftest
    assert not is_test_path("latest_release.py")   # 'test' substring, not a segment
    assert not is_test_path("attestation.ts")


def test_walk_skips_next_build_output(tmp_path: Path) -> None:
    _make(tmp_path, "src/app.py")
    _make(tmp_path, "out/_next/static/chunks/514-abc.js", "var weave=1")
    names = sorted(p.name for p in walk_files(str(tmp_path)))
    assert "app.py" in names
    assert "514-abc.js" not in names


def test_walk_skip_tests_excludes_test_paths(tmp_path: Path) -> None:
    _make(tmp_path, "app/main.py")
    _make(tmp_path, "tests/test_main.py")
    _make(tmp_path, "src/__tests__/x.ts")
    _make(tmp_path, "lib/util.spec.ts")
    got = {p.relative_to(tmp_path).as_posix() for p in walk_files(str(tmp_path), skip_tests=True)}
    assert "app/main.py" in got
    assert "tests/test_main.py" not in got
    assert "src/__tests__/x.ts" not in got
    assert "lib/util.spec.ts" not in got
    # default (skip_tests=False) keeps everything
    allf = {p.relative_to(tmp_path).as_posix() for p in walk_files(str(tmp_path))}
    assert "tests/test_main.py" in allf
