"""Tests for the gitignore-aware file walker."""
from __future__ import annotations

from pathlib import Path

from ai_surface.utils.walk import read_text_safe, walk_files


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
