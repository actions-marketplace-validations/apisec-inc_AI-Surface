"""ai-surface CLI entry point."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import typer
from rich.console import Console

from . import __version__
from .orchestrator import Orchestrator, default_detectors
from .types import (
    ALL_CATEGORIES,
    CATEGORY_AGENT_FRAMEWORK,
    CATEGORY_AI_INFRA,
    CATEGORY_ENV_KEY,
    CATEGORY_LLM_SDK,
    CATEGORY_MCP_SERVER,
    CATEGORY_MODEL_GATEWAY,
)

app = typer.Typer(
    name="ai-surface",
    help="Inventory production AI surfaces in your application code.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


# Friendly aliases for category names so users can type --categories mcp,agents
# instead of --categories mcp-server,agent-framework.
CATEGORY_ALIASES: Dict[str, str] = {
    # MCP
    "mcp": CATEGORY_MCP_SERVER,
    "mcp-server": CATEGORY_MCP_SERVER,
    "mcp-servers": CATEGORY_MCP_SERVER,
    "mcps": CATEGORY_MCP_SERVER,
    # Agent frameworks
    "agent": CATEGORY_AGENT_FRAMEWORK,
    "agents": CATEGORY_AGENT_FRAMEWORK,
    "agent-framework": CATEGORY_AGENT_FRAMEWORK,
    "agent-frameworks": CATEGORY_AGENT_FRAMEWORK,
    # LLM SDKs
    "llm": CATEGORY_LLM_SDK,
    "llms": CATEGORY_LLM_SDK,
    "llm-sdk": CATEGORY_LLM_SDK,
    "llm-sdks": CATEGORY_LLM_SDK,
    "sdk": CATEGORY_LLM_SDK,
    "sdks": CATEGORY_LLM_SDK,
    # Model gateways
    "gateway": CATEGORY_MODEL_GATEWAY,
    "gateways": CATEGORY_MODEL_GATEWAY,
    "model-gateway": CATEGORY_MODEL_GATEWAY,
    "model-gateways": CATEGORY_MODEL_GATEWAY,
    # AI infra
    "infra": CATEGORY_AI_INFRA,
    "ai-infra": CATEGORY_AI_INFRA,
    # Env keys
    "env": CATEGORY_ENV_KEY,
    "env-key": CATEGORY_ENV_KEY,
    "env-keys": CATEGORY_ENV_KEY,
    "keys": CATEGORY_ENV_KEY,
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _resolve_categories(requested: Optional[str]) -> Optional[Set[str]]:
    """Parse --categories input into a set of canonical category names.

    Returns None when `requested` is None (meaning "all categories").
    Raises typer.Exit on invalid input.
    """
    if not requested:
        return None
    parts = [p.strip().lower() for p in requested.split(",") if p.strip()]
    if not parts:
        return None
    canonical: Set[str] = set()
    invalid: List[str] = []
    for p in parts:
        if p in ALL_CATEGORIES:
            canonical.add(p)
        elif p in CATEGORY_ALIASES:
            canonical.add(CATEGORY_ALIASES[p])
        else:
            invalid.append(p)
    if invalid:
        valid_names = sorted(set(ALL_CATEGORIES))
        err_console.print(
            f"[red]error[/red]: unknown category/categories: {', '.join(invalid)}"
        )
        err_console.print(f"[dim]valid categories: {', '.join(valid_names)}[/dim]")
        err_console.print(
            "[dim]aliases accepted: mcp, agents, llm, gateway, infra, keys[/dim]"
        )
        raise typer.Exit(code=2)
    return canonical


def _filter_detectors_by_category(detectors: list, allowed: Optional[Set[str]]) -> list:
    """Return only detectors whose category is in `allowed`, or all if None."""
    if allowed is None:
        return list(detectors)
    return [d for d in detectors if getattr(d, "category", None) in allowed]


def _print_quiet_summary(report) -> None:
    """One-line summary for CI / scripted use."""
    surfaces = len(report.findings)
    risks = sum(len(f.risk_indicators) for f in report.findings)
    detectors = len(report.detectors_run)
    errors = len(report.errors)
    parts = [f"{surfaces} surfaces", f"{risks} risks"]
    if errors:
        parts.append(f"{errors} errors")
    parts.append(f"{detectors} detectors")
    console.print(f"ai-surface: {', '.join(parts)}")


@app.command()
def scan(
    path: str = typer.Argument(".", help="Directory to scan."),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, json, markdown.",
    ),
    categories: Optional[str] = typer.Option(
        None,
        "--categories",
        "-c",
        help=(
            "Comma-separated categories to scan. "
            "Aliases: mcp, agents, llm, gateway, infra, keys. "
            "Default: all."
        ),
    ),
    write_inventory: bool = typer.Option(
        False,
        "--write-inventory",
        help="Generate .ai-inventory.md alongside the terminal output.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="One-line summary output for CI / scripts. Suppresses other output.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Verbose: show all files (no truncation), full detector errors.",
    ),
) -> None:
    """Scan PATH for production AI surfaces and report what's there."""
    _setup_logging(verbose)

    root = Path(path).resolve()
    if not root.is_dir():
        err_console.print(f"[red]error[/red]: {path} is not a directory")
        raise typer.Exit(code=2)

    allowed_categories = _resolve_categories(categories)

    detectors = default_detectors()
    detectors = _filter_detectors_by_category(detectors, allowed_categories)
    if not detectors:
        if allowed_categories:
            err_console.print(
                f"[red]error[/red]: no detectors match categories: "
                f"{', '.join(sorted(allowed_categories))}"
            )
            raise typer.Exit(code=2)
        err_console.print(
            "[yellow]warning[/yellow]: no detectors registered yet. "
            "v0.5 detectors are still being implemented."
        )

    orch = Orchestrator(detectors=detectors)
    report = orch.run(str(root))

    # Quiet mode short-circuits all reporters and prints a single line.
    if quiet:
        _print_quiet_summary(report)
        return

    # Render based on requested output
    if output == "json":
        from .reporters.json_reporter import render_json  # noqa: PLC0415

        console.print_json(render_json(report))
    elif output == "markdown":
        from .reporters.markdown_reporter import render_markdown  # noqa: PLC0415

        console.print(render_markdown(report))
    else:
        # terminal is default
        try:
            from .reporters.terminal_reporter import render_terminal  # noqa: PLC0415

            render_terminal(report, console, verbose=verbose)
        except ImportError:
            # Fallback: dump findings as JSON if terminal reporter not yet built
            data = {
                "schema_version": report.schema_version,
                "tool_version": report.tool_version,
                "scan_root": report.scan_root,
                "scan_timestamp": report.scan_timestamp,
                "detectors_run": report.detectors_run,
                "findings_count": len(report.findings),
                "findings": [
                    {
                        "surface": f.surface,
                        "category": f.category,
                        "permissions": f.permissions,
                        "risk_indicators": f.risk_indicators,
                        "files": f.evidence.files,
                    }
                    for f in report.findings
                ],
                "errors": report.errors,
            }
            console.print_json(json.dumps(data))

    if write_inventory:
        try:
            from .reporters.markdown_reporter import render_markdown  # noqa: PLC0415

            inv_path = root / ".ai-inventory.md"
            inv_path.write_text(render_markdown(report), encoding="utf-8")
            err_console.print(f"[green]wrote[/green] {inv_path}")
        except ImportError:
            err_console.print(
                "[yellow]warning[/yellow]: --write-inventory requested but "
                "markdown reporter not yet implemented."
            )


@app.command()
def compare(
    base: str = typer.Argument(..., help="Path to the base JSON report (older)."),
    head: str = typer.Argument(..., help="Path to the head JSON report (newer)."),
    output: str = typer.Option(
        "markdown",
        "--output",
        "-o",
        help="Output format: markdown, json.",
    ),
) -> None:
    """Compare two JSON scan reports and print the AI surface changes."""
    from .diff import (  # noqa: PLC0415
        compute_diff,
        diff_to_dict,
        load_report_from_json,
        render_diff_markdown,
    )

    try:
        base_text = Path(base).read_text(encoding="utf-8")
        head_text = Path(head).read_text(encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]error[/red]: cannot read input: {exc}")
        raise typer.Exit(code=2) from exc

    try:
        base_report = load_report_from_json(base_text)
        head_report = load_report_from_json(head_text)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        err_console.print(f"[red]error[/red]: invalid JSON report: {exc}")
        raise typer.Exit(code=2) from exc

    diff = compute_diff(base_report, head_report)

    if output == "json":
        console.print_json(json.dumps(diff_to_dict(diff)))
    else:
        # markdown is default
        console.print(render_diff_markdown(diff))


@app.command()
def version() -> None:
    """Print ai-surface version."""
    console.print(f"ai-surface {__version__}")


def main() -> None:
    """Entrypoint for the `ai-surface` console_script."""
    app()


if __name__ == "__main__":
    main()
