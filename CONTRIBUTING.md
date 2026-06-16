# Contributing to ai-surface

Thanks for your interest. `ai-surface` is built to be useful and accurate; improvements that move it in either direction are welcome.

## What we want

- **New detector coverage.** Languages, frameworks, or AI providers we don't catch yet.
- **False-positive fixes.** A finding that shouldn't have fired, with a minimal reproducer.
- **False-negative fixes.** A surface that exists in real code but `ai-surface` missed.
- **Performance work.** Especially on monorepos and polyglot codebases.
- **Documentation.** Anywhere a reader has to guess at intent.

## What we'll push back on

- **Runtime testing features.** This tool is static, source-side, no-runtime by design. Runtime exploit validation lives in the APIsec platform.
- **Detection of cross-application chains.** `ai-surface` indexes one codebase at a time. Cross-app composite views are out of scope here.
- **Generic security scanning** (secrets in all code, dependency CVEs, container scans). Use the right tool for that job: trufflehog, dependabot, trivy. We focus on AI surfaces specifically.

## Development setup

```bash
git clone https://github.com/apisec-inc/AI-Surface
cd ai-surface
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Tests must pass before a PR is reviewed. Aim for the test suite to stay under one second.

## Adding a detector

1. Create `src/ai_surface/detectors/your_category.py` implementing the `Detector` protocol from `types.py`.
2. Register the detector in `default_detectors()` in `orchestrator.py`.
3. Add fixtures and tests under `tests/`. Cover the positive case, at least one false-positive resistance case, and one edge case (malformed input, empty file, unicode).
4. Update the README's "What it detects" table.

## Reporting issues

Use the issue templates. Minimal reproducer beats long prose. If you can attach a sanitized snippet of the code that did or did not produce a finding, that's gold.

## Pull requests

- One concern per PR.
- Tests required for any code change.
- Update CHANGELOG.md under "Unreleased."
- Match existing code style (`ruff check`, `mypy`).
- The PR description should explain why, not just what.

## License

By contributing, you agree your contributions are licensed under the MIT License (see `LICENSE`).
