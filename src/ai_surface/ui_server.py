"""Local UI viewer for `ai-surface scan --ui`.

Serves the static UI (ui/ assets) together with the current scan rendered as
report.json, over http://localhost so the UI's `fetch("./report.json")` works
(file:// would be blocked by the browser). The UI does no scanning; it only
renders the engine's schema-1.0 JSON.

Privacy: served on loopback only, from a throwaway temp directory. No network
egress, no telemetry.
"""
from __future__ import annotations

import shutil
import tempfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .reporters.json_reporter import render_json
from .types import Report

#: Static asset files the viewer needs alongside report.json.
_UI_ASSETS = ("index.html", "styles.css", "app.js")


def ui_asset_dir() -> Path | None:
    """Locate the bundled UI assets.

    Prefers a packaged location (src/ai_surface/ui, for shipped wheels) and
    falls back to the repo-root ui/ used in source/editable installs. Returns
    None if the assets cannot be found.
    """
    candidates = [
        Path(__file__).resolve().parent / "ui",  # packaged (future wheel layout)
        Path(__file__).resolve().parents[2] / "ui",  # repo-root (dev / source)
    ]
    for c in candidates:
        if (c / "index.html").is_file():
            return c
    return None


def prepare_ui_dir(report: Report, dest: Path | None = None) -> Path:
    """Materialize a self-contained UI directory: the static assets plus a
    freshly rendered report.json. Returns the directory path.

    Factored out of serve_ui so it is testable without starting a server.
    Raises FileNotFoundError if the UI assets are missing.
    """
    assets = ui_asset_dir()
    if assets is None:
        raise FileNotFoundError(
            "ai-surface UI assets not found (expected a ui/ directory with "
            "index.html). The --ui viewer is unavailable in this install."
        )

    dest = dest or Path(tempfile.mkdtemp(prefix="ai-surface-ui-"))
    dest.mkdir(parents=True, exist_ok=True)
    for name in _UI_ASSETS:
        src = assets / name
        if src.is_file():
            shutil.copy2(src, dest / name)
    (dest / "report.json").write_text(render_json(report) + "\n", encoding="utf-8")
    return dest


def serve_ui(report: Report, port: int = 0, open_browser: bool = True) -> None:
    """Serve the UI for a report on loopback and (optionally) open a browser.

    Blocks until interrupted (Ctrl-C). port=0 lets the OS pick a free port.
    """
    serve_dir = prepare_ui_dir(report)
    handler = partial(SimpleHTTPRequestHandler, directory=str(serve_dir))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    actual_port = httpd.server_address[1]
    url = f"http://localhost:{actual_port}/index.html"

    print(f"ai-surface UI: {url}")
    print("serving the local viewer. press Ctrl-C to stop.")
    if open_browser:
        try:
            import webbrowser  # noqa: PLC0415

            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - opening a browser is best-effort
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping UI server.")
    finally:
        httpd.server_close()
