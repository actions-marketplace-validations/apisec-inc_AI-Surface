# ai-surface

**Inventory the production AI surfaces in your application code.**

Your application code is shipping production AI surfaces faster than DevOps can govern them. `ai-surface` runs in your CI on every PR and surfaces every LLM call, agent, MCP server, and model gateway your services are about to expose to production. With permissions and risk indicators.

```
$ ai-surface scan .

AI Surface Report
────────────────────────────────────────────────────────────────
Scanned: /path/to/repo
7 production AI surfaces · 9 risk indicators · across 5 detector(s)

LLM SDK CALL SITES
  • Anthropic SDK
      Models: claude-sonnet-4-6
      → src/agents/refund.py
      ⚠ non-literal data flows into LLM call
      → validate this surface

AGENT FRAMEWORKS
  • LangChain Agent: refund_agent (in src/agents/refund.py)
      Tools/perms: query_db, refund_payment
      ⚠ financial action exposed
      ⚠ high blast-radius combination
      → validate this surface
  • CrewAI Agent: researcher (in src/research/crew.py)
      Tools/perms: search_tool, send_email_tool
      ⚠ high blast-radius combination
      → validate this surface

MCP SERVERS
  • MCP Server: github-mcp
      Tools/perms: admin, write, repo:read
      → .mcp.json
      ⚠ broad permissions
      → validate this surface
  • MCP Server (in-house): src/mcp/orders_server.py
      Tools/perms: lookup_order, refund_payment, cancel_order
      ⚠ in-house MCP server (custom code, audit recommended)
      ⚠ financial action exposed
      → validate this surface

────────────────────────────────────────────────────────────────
For deep mcp server analysis: mcp-audit
Validate which surfaces are exploitable: apisec.ai/ai-validation
```

Each finding with risk indicators links to APIsec for runtime exploit
validation. MCP findings additionally point at [mcp-audit](https://github.com/apisec-inc/mcp-audit)
for deep MCP-specific analysis.

## What this is for

DevOps, Platform, and SRE engineers governing what AI ships into production. Not what AI tools your developers use locally — Cursor, Claude Code, and Copilot live in a different conversation. This is about what AI lives in the application code that ships to customers.

The job is to make AI surfaces visible and reviewable at PR time, before they reach production.

## Status

**v0.5 alpha.** Code-side detection across 5 categories. CLI works end to end. GitHub Action ships in this version. Stable on real APIsec internal repos. Roadmap below.

## Install

```bash
# Run without installing (recommended for first use)
pipx run ai-surface scan .

# Or install globally
pipx install ai-surface
ai-surface scan .

# Or in a project venv
pip install ai-surface
ai-surface scan .
```

Requires Python 3.9 or newer.

## GitHub Action

Drop this into `.github/workflows/ai-surface.yml`:

```yaml
name: AI Surface Check
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  ai-surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }    # required for base-vs-head diff
      - uses: apisec-inc/ai-surface@v0
        with:
          path: '.'
          comment-on-pr: 'true'
          fail-on-risk: 'false'
```

Every PR gets a sticky comment showing **what changed in this PR**, not just the current state. Example diff comment:

```markdown
### 🤖 AI Surface Changes

**1 new, 1 modified**

### ➕ New AI surfaces

- **MCP Server: stripe-mcp**
  - Tools/permissions: `read_charges`, `refund`
  - Files: `.mcp.json`
  - ⚠️ broad permissions
  - ⚠️ financial action exposed

### ✏️ Modified AI surfaces

- **LangChain Agent: refund_agent (in src/agents/refund.py)**
  - ➕ Permissions added: `cancel_subscription`
  - ⚠️ Risk added: high blast-radius combination
```

When the base branch isn't reachable (push event, first PR ever, fork PR without base history), the comment falls back to a full inventory of the current state.

Set `fail-on-risk: 'true'` to block PRs that introduce any risk indicators.

## What it detects (v0.5)

| Category | Detected |
|---|---|
| **MCP servers** | Configured (`.mcp.json`, `mcp_servers/`) and source-resident in-house servers (Python `FastMCP`, `mcp.Server`, JS `@modelcontextprotocol/sdk`). Tool catalogs and capabilities. |
| **LLM SDK call sites** | Anthropic, OpenAI, Azure OpenAI, AWS Bedrock, Google Generative AI, Vertex AI, Together, Mistral, Cohere, Replicate, Groq, LiteLLM. Models extracted, data-flow risk flagged. |
| **Agent frameworks** | LangChain, LangGraph, CrewAI, LlamaIndex, AutoGen, Haystack, Semantic Kernel, Pydantic AI, plus Anthropic-shape `tools=[{...}]`. Tool inventories per agent. |
| **AI provider env keys** | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AZURE_OPENAI_*`, `GROQ_API_KEY`, `LANGSMITH_API_KEY`, etc. across `.env` files. **Names only, never values.** |
| **Model gateways and AI infra** | LiteLLM proxy configs, Portkey, Helicone, Cloudflare AI Gateway, Kubernetes deployments running ollama/vllm/text-generation-inference, Terraform Bedrock provisioned throughput. |

### Risk indicators v0.5 understands

- `broad permissions` (MCP server with admin/write/delete capabilities)
- `in-house MCP server (custom code, audit recommended)`
- `financial action exposed` (tool names containing refund/payment/charge/transfer)
- `destructive action exposed` (delete/drop/truncate/purge)
- `messaging action exposed` (send_email/send_slack/send_sms)
- `database write exposed`
- `high blast-radius combination` (agent with both read AND destructive/financial tools)
- `non-literal data flows into LLM call` (variable references in `messages=` or `prompt=`)
- `multiple AI provider keys present`
- `observability/tracing key present (production telemetry to third party)`
- `multi-model routing layer (production traffic flows through this)`
- `self-hosted LLM runtime (operational responsibility on the team)`
- `high-cost AI infrastructure (billing exposure)`

## What it generates

Three output formats:

```bash
ai-surface scan .                          # pretty terminal
ai-surface scan . --output json            # machine-readable JSON
ai-surface scan . --output markdown        # markdown report
ai-surface scan . --write-inventory        # writes .ai-inventory.md to scan root
```

The `.ai-inventory.md` file is a committable artifact. Engineers browsing the repo see the AI surfaces in the same place they read everything else. The GitHub Action uses it as the diff baseline for PR comments.

## What it does not do (yet)

- Runtime telemetry or behavior monitoring (use Helicone, LangSmith, Arize for that)
- Live cluster scanning (planned for v0.7)
- Multi-repo or org-wide rollup (planned for v0.6)
- Prompt injection or LLM behavior testing (different problem; out of scope by design)
- Cross-file dataflow for tool resolution (regex-based v0.5; AST in v0.6)

## CLI commands

```bash
# Scan and report
ai-surface scan .                                # pretty terminal
ai-surface scan . --output json                  # machine-readable
ai-surface scan . --output markdown              # markdown
ai-surface scan . --write-inventory              # generates .ai-inventory.md

# Filter to specific categories
ai-surface scan . --categories mcp               # MCP servers only
ai-surface scan . --categories agents,llm        # agents + LLM SDKs
# Aliases: mcp, agents, llm, gateway, infra, keys

# CI / scripted use
ai-surface scan . --quiet                        # one-line summary
                                                 # → ai-surface: 7 surfaces, 9 risks, 5 detectors

# Verbose mode
ai-surface scan . --verbose                      # show all files (no truncation),
                                                 # surface detector errors

# Compare two scans (used by the GitHub Action under the hood)
ai-surface scan . --output json > base.json
git checkout pr-branch
ai-surface scan . --output json > head.json
ai-surface compare base.json head.json           # markdown diff
ai-surface compare base.json head.json --output json
```

## Roadmap

- **v0.5** (current alpha): code-side detection, terminal + JSON + markdown reporters, GitHub Action with PR diff comments, base-vs-head comparison, basic risk indicators
- **v0.6**: `.ai-surface.yml` policy file (allowlists, fail-on triggers), GitLab CI component, AST-based tool resolution, multi-document YAML
- **v0.7**: kubectl plugin, live cluster discovery, GitHub repo settings ingestion
- **v0.8**: continuous mode, drift alerts, multi-repo rollup, hosted dashboard option
- **v1.0**: stable schema, plugin SDK for custom detectors, performance work for monorepos

## Why this lives at code time, not at runtime

Most AI security and observability tools see AI activity AFTER it ships: `Helicone`, `LangSmith`, `Arize` show what got called in production. `Wiz` and cloud platforms see what got deployed. They are useful and complementary.

`ai-surface` runs at the moment a developer is about to merge a change. It catches new MCP servers, widened permissions, agents with refund authority, and PII flowing into LLM calls before they exist in production. PR-time visibility is materially different from post-deploy telemetry, and it is where DevOps governance has the cheapest control point.

## Cross-sell

`ai-surface` tells you what AI surfaces exist. To validate which ones are actually exploitable in a running application — agent-to-tool authorization, integration chain exploits, BOLA across the agent layer, dual-evidence findings backed by code AND runtime — see [APIsec](https://apisec.ai/ai-validation).

## Development

```bash
git clone https://github.com/apisec-inc/ai-surface
cd ai-surface
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The codebase is structured for parallel detector development:

```
src/ai_surface/
├── cli.py                  # Typer entry point
├── orchestrator.py         # Runs detectors, aggregates findings
├── types.py                # Finding, Detector protocol, Report
├── detectors/              # One module per detector
│   ├── mcp_servers.py
│   ├── llm_sdks.py
│   ├── agent_frameworks.py
│   ├── env_keys.py
│   └── model_gateways.py
├── reporters/              # Output renderers
│   ├── terminal_reporter.py
│   ├── json_reporter.py
│   └── markdown_reporter.py
└── utils/walk.py           # gitignore-aware file walker
```

Adding a detector: implement the `Detector` protocol in `types.py`, register in `default_detectors()`, add fixtures + tests under `tests/`.

## License

MIT. See [LICENSE](LICENSE).
