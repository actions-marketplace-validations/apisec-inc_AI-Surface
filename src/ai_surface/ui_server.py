"""Local UI viewer for `ai-surface scan --ui`.

Serves the static UI (ui/ assets) together with the current scan rendered as
report.json, over http://localhost so the UI's `fetch("./report.json")` works
(file:// would be blocked by the browser). The UI does no scanning; it only
renders the engine's schema-1.0 JSON.

Privacy: served on loopback only, from a throwaway temp directory. No network
egress, no telemetry.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .reporters.json_reporter import render_json, report_to_dict
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
    # Also emit the AI-BOM so the UI can offer a one-click download (and the
    # hosted demo can ship it as a static file).
    from .reporters.cyclonedx_reporter import render_cyclonedx  # noqa: PLC0415

    (dest / "ai-bom.json").write_text(render_cyclonedx(report) + "\n", encoding="utf-8")
    return dest


def scan_for_request(
    repo_url: str | None = None,
    path: str | None = None,
    token: str | None = None,
) -> Report:
    """Run a scan for a UI /api/scan request and return the Report.

    A repo_url is cloned locally (and discarded); otherwise a local path is
    scanned (default "."). Raises RepoError or FileNotFoundError on bad input.
    """
    from .orchestrator import Orchestrator, default_detectors  # noqa: PLC0415

    if repo_url:
        from .repo import clone_repo  # noqa: PLC0415

        with clone_repo(repo_url, token) as cloned:
            return Orchestrator(default_detectors()).run(str(cloned))

    target = _resolve_local_path(path)
    return Orchestrator(default_detectors()).run(str(target))


def _resolve_local_path(path: str | None) -> Path:
    """Resolve a UI-entered local path to an existing directory.

    Forgiving of two common slips when typing a path into the form:
      * a "~" home prefix (expanded), and
      * a dropped leading slash on an absolute path (e.g. "Users/me/proj"
        instead of "/Users/me/proj"), which would otherwise resolve against
        the server's working directory and fail confusingly.
    """
    raw = (path or ".").strip()
    candidate = Path(raw).expanduser()
    if candidate.is_dir():
        return candidate.resolve()
    # Dropped-leading-slash recovery: only when it actually points at a dir.
    if not raw.startswith(("/", "~", ".")):
        slashed = Path("/" + raw)
        if slashed.is_dir():
            return slashed.resolve()
    raise FileNotFoundError(
        f"not a directory: {raw}. Use an absolute path, e.g. "
        f"/Users/you/project (include the leading slash)."
    )


class _UIRequestHandler(SimpleHTTPRequestHandler):
    """Serves the static UI (GET) and handles POST /api/scan (local scans).

    Bound to loopback only, so only local processes can trigger a scan. A token
    in the request body is used for the clone and never persisted or logged.
    """

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        if self.path.split("?", 1)[0].rstrip("/") != "/api/scan":
            self.send_error(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except (ValueError, TypeError):
            self._send_json(400, {"error": "invalid JSON body"})
            return

        from .repo import RepoError  # noqa: PLC0415

        try:
            report = scan_for_request(
                repo_url=req.get("repo_url"),
                path=req.get("path"),
                token=req.get("token"),
            )
        except (RepoError, FileNotFoundError) as exc:
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - never crash the server
            self._send_json(500, {"error": f"scan failed: {exc.__class__.__name__}"})
            return

        self._send_json(200, report_to_dict(report))

    def _send_json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # noqa: A002 - silence access log
        pass


def serve_ui(report: Report, port: int = 0, open_browser: bool = True) -> None:
    """Serve the UI for a report on loopback and (optionally) open a browser.

    Blocks until interrupted (Ctrl-C). port=0 lets the OS pick a free port.
    The server also answers POST /api/scan so the UI can run further local
    scans (a path or a remote repo) without restarting.
    """
    serve_dir = prepare_ui_dir(report)
    handler = partial(_UIRequestHandler, directory=str(serve_dir))
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
