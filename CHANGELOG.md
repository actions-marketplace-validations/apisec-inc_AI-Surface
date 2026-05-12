# Changelog

All notable changes to `ai-surface` will be documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-05-12

### Added

- AWS Strands SDK detection (`from strands import Agent`, `from strands.models import BedrockModel`). Adds named-agent findings for `agent = Agent(model=..., tools=...)` patterns common in Strands code.
- Bedrock model-ID regex now accepts cross-region inference profile prefixes (e.g. `us.anthropic.claude-sonnet-4-...`, `eu.anthropic.claude-...`).
- Agent regex now matches indented assignments inside functions (previously only module-level Agent declarations were captured).
- Repo hygiene for public release: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue templates, PR template, PyPI Trusted Publisher workflow.
- Expanded README with "How it works (and what stays local)" section, Troubleshooting section, and explicit static-analysis / no-runtime / no-auth framing.
- Terraform parser handles nested braces, HCL heredocs (`<<EOT ... EOT`, `<<-EOT ... EOT`), and `/* ... */` block comments. Previous `[^}]*` body capture silently truncated bodies at the first inner `}`.

### Changed

- Detector name `mcp-servers` is now `mcp_servers` for consistency with the other detector identifiers (`env_keys`, `llm_sdks`, `agent_frameworks`, `model_gateways`). Anyone scripting against the detector list should update; the CLI alias `--categories mcp-servers` continues to work.
- Cross-promotion deep-link query parameter renamed from `?surface=` to `?category=` since the value being passed is the finding's category, not its surface name. The APIsec validation landing page accepts both during the v0.5 transition.
- `Report.scan_root` now contains the basename of the scan root (e.g. `demo-app`) rather than the resolved absolute filesystem path. Reports are routinely committed to git or posted as PR comments, and absolute paths leak the user's home directory, employer name, and internal mount layout. Detectors continue to receive the resolved path internally.
- File walker is documented as honouring the **root** `.gitignore` only. Nested per-directory `.gitignore` files, `.git/info/exclude`, and the global git excludesfile are not consulted (the implementation was always this narrow; the docs previously implied otherwise).

### Security

- GitHub Action refuses to run under the `pull_request_target` event. That event combines repo write secrets with attacker-controlled PR code and is the canonical supply-chain vector for Actions. The Action exits with an error before any input is read or scan is invoked. Use the `pull_request` event instead; for fork PRs, the recommended pattern is a downstream `workflow_run` workflow that consumes the artifact produced by the safe `pull_request` run.
- File walker enforces hard resource caps to prevent denial-of-service on pathological trees: `MAX_FILES = 250,000` per traversal, `MAX_TOTAL_BYTES = 5 GiB` cumulative content size accounted via `os.lstat`. A symlink to a 100 GiB blob outside the tree contributes the symlink's own inode size (~40 bytes), not the target's.
- `read_text_safe` refuses symlinks outright (`S_ISLNK` check after `os.lstat`) and re-bounds reads at `max_bytes` as defence-in-depth against TOCTOU races between stat and open.
- `relative_to_root` no longer falls back to the absolute path when a path lies outside the scan root. Returns `<outside-root>/{basename}` instead so the report makes it visible that a path was redacted rather than silently truncated.
- Fixed ReDoS in agent-framework constructor patterns. Previous DOTALL + lazy-quantifier regexes for crewai / autogen made the detector quadratic on adversarial input (~5 s per 5 K unmatched `Agent(` tokens, unresponsive at 5 MB). Patterns now anchor only the constructor opening; the body is extracted by a bracket-balanced scanner with per-call (16 KB) and per-file (256-attempt) caps. A regression test pins 5 MB of adversarial input under 8 s.
- Fixed markdown injection in PR comment and inventory output. Snippets are now wrapped in a length-aware code fence longer than any internal backtick run, so an attacker source line containing ``` cannot break out of the fence. Surface names, file paths, permissions, and risk indicators flow through a shared sanitiser that strips control characters, angle brackets, backticks, and leading markdown structural characters.

### Fixed

- `_PROMPT_NONLITERAL` flow detector no longer flags `None`, `True`, `False`, or other Python keywords as "non-literal data flow into LLM call."
- Word-boundary tokenisation in broad-permission / financial-action classifiers eliminates substring false positives (`install_app` no longer matches `all`, `customer_address` no longer matches `customer`, etc.).
- LLM SDK detector resolves model names to the SDK they belong to via affinity heuristics, so a file using both Anthropic and OpenAI SDKs no longer cross-attributes models.
- LangChain `AgentExecutor(agent=...)` wraps are now recognised and merged with the underlying agent rather than emitting a duplicate finding.

## [0.5.0] - 2026-05-11

Initial public alpha release.

### Added

- Static-analysis detection across 5 AI surface categories:
  - LLM SDK call sites (12+ providers: Anthropic, OpenAI, Azure OpenAI, AWS Bedrock, Google Generative AI, Vertex AI, Together, Mistral, Cohere, Replicate, Groq, LiteLLM)
  - Agent frameworks (8+ frameworks: LangChain, LangGraph, CrewAI, LlamaIndex, AutoGen, Haystack, Semantic Kernel, Pydantic AI, plus Anthropic-shape tool definitions)
  - MCP servers (configured and in-house, Python `FastMCP` + `mcp.Server`, JS `@modelcontextprotocol/sdk`)
  - AI provider environment variable names (names only, never values)
  - Model gateways and AI infrastructure (LiteLLM, Portkey, Helicone, Cloudflare AI Gateway, self-hosted runtimes via Kubernetes/Terraform)
- 13 named risk indicators with conservative semantics (broad permissions, financial action exposed, destructive action exposed, blast-radius combinations, non-literal data flow, etc.)
- Three output formats: rich terminal, JSON, markdown
- Committable `.ai-inventory.md` artifact
- Base-vs-head diff engine for PR comment generation
- GitHub Action wrapper with sticky PR comments showing surface changes
- Cross-promotion links to specialist tools (mcp-audit) and the APIsec platform
- Verbose mode for debugging detector errors

### Known limitations in v0.5

- Regex-based tool resolution (AST coming in v0.6)
- Single-document YAML parsing only
- No live cluster scanning (planned for v0.7)
- No multi-repo aggregation (planned for v0.8)
