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
