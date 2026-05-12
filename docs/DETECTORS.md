# Detector Coverage Matrix

Complete list of what each `ai-surface` detector finds, the patterns it matches, and the risk indicators it can raise.

This document is the **detection contract**. If you're evaluating whether `ai-surface` will see your AI surfaces, scan this list. If something's missing, [file a false-negative issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-negative.yml) with a minimal reproducer.

## Contents

- [LLM SDK call sites](#llm-sdk-call-sites)
- [Agent frameworks](#agent-frameworks)
- [MCP servers](#mcp-servers)
- [AI provider env keys](#ai-provider-env-keys)
- [Model gateways and AI infrastructure](#model-gateways-and-ai-infrastructure)
- [Risk indicator vocabulary](#risk-indicator-vocabulary)
- [Known limitations](#known-limitations)

## LLM SDK call sites

Detector: `src/ai_surface/detectors/llm_sdks.py`

Scans Python (`.py`) and JavaScript/TypeScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`) source for LLM provider SDK usage. Extracts model names and flags data-flow risks.

### Providers detected

| Provider | Python pattern | JS/TS pattern |
|---|---|---|
| **Anthropic SDK** | `from anthropic import` / `Anthropic()` constructor | `@anthropic-ai/sdk` import |
| **OpenAI SDK** | `from openai import` / `OpenAI()` constructor | `openai` import |
| **Azure OpenAI** | `from openai import AzureOpenAI` / `AzureOpenAI(...)` | `AzureOpenAI` in code, `AZURE_OPENAI_*` env refs |
| **AWS Bedrock (direct)** | `boto3.client("bedrock(-runtime)")` | `@aws-sdk/client-bedrock-runtime` |
| **AWS Bedrock (Strands)** | `from strands.models import BedrockModel`, `BedrockModel(...)` | _none_ |
| **Google Generative AI** | `from google.generativeai` | `@google/generative-ai` |
| **Google Vertex AI** | `from vertexai`, `from google.cloud import aiplatform` | `@google-cloud/aiplatform` |
| **Together** | `from together` | `together-ai` |
| **Mistral** | `from mistralai` | `@mistralai/mistralai` |
| **Cohere** | `from cohere` | `cohere-ai` |
| **Replicate** | `from replicate` | `replicate` |
| **Groq** | `from groq` | `groq-sdk` |
| **LiteLLM** | `from litellm` | _none_ |

### Models extracted

Recognized model name patterns:

- `claude-*` (Anthropic models, including `claude-sonnet-*`, `claude-haiku-*`, `claude-opus-*`)
- `anthropic.claude-*` with version suffix (Bedrock format)
- `(us|eu|apac).anthropic.claude-*` (Bedrock cross-region inference profiles)
- `gpt-*`, `o1`, `o2`, `o3`, `text-embedding-*` (OpenAI)
- `amazon.titan-*`, `amazon.nova-*` (Bedrock)
- `(us|eu|apac).amazon.titan-*`, `(us|eu|apac).amazon.nova-*`
- `meta.llama*` (Bedrock Llama)
- `(us|eu|apac).meta.llama*`
- `mistral.*`, `(us|eu|apac).mistral.*` (Bedrock Mistral)
- `cohere.command-*`, `(us|eu|apac).cohere.command-*`
- Generic: `llama-*`, `mistral-*`, `mixtral-*`, `command-*`, `gemini-*`

### Risk indicators

- `non-literal data flows into LLM call`: variable references in `messages=` or `prompt=` kwargs (regex-based today; AST in v0.6 for higher precision)

## Agent frameworks

Detector: `src/ai_surface/detectors/agent_frameworks.py`

Scans Python source for agent framework imports, named agent definitions, and per-agent tool inventories.

### Frameworks detected

| Framework | Display name | Import roots | Specific pattern |
|---|---|---|---|
| **LangGraph** | LangGraph | `langgraph` | `StateGraph()`, `MessageGraph()` |
| **LangChain** | LangChain | `langchain`, `langchain_core`, `langchain_community` | `AgentExecutor`, `initialize_agent`, `create_react_agent`, `create_openai_tools_agent`, `create_tool_calling_agent` |
| **CrewAI** | CrewAI | `crewai` | `Agent(role=...)` or `Agent(name=...)` |
| **LlamaIndex** | LlamaIndex | `llama_index` | _none_ |
| **AutoGen** | AutoGen | `autogen` | `AssistantAgent()`, `UserProxyAgent()` |
| **Haystack** | Haystack | `haystack` | _none_ |
| **Semantic Kernel** | Semantic Kernel | `semantic_kernel` | _none_ |
| **Pydantic AI** | Pydantic AI | `pydantic_ai` | `agent = Agent(...)` |
| **AWS Strands** | AWS Strands | `strands` | `agent = Agent(model=..., tools=...)`, `@tool` decorators |

### Tool extraction methods

For each named agent, `ai-surface` tries to extract tool inventories from (in priority order):

1. `tools=[Tool(name="x", ...), ...]` block inside the agent constructor
2. The nearest `tools=[...]` block in the same file (within 30 lines)
3. `@tool` or `@strands_tool` decorated functions in the same file
4. Anthropic-shape `tools=[{"name": "x"}, ...]` dict literals

### Risk indicators

- `financial action exposed`: tool name contains `refund`, `payment`, `charge`, `transfer`, `withdraw`, `payout`, `invoice`
- `destructive action exposed`: tool name contains `delete`, `drop`, `truncate`, `remove`, `purge`, `destroy`
- `messaging action exposed`: tool name is `send_email`, `send_message`, `send_slack`, `send_sms`, or `post_to_*`
- `database write exposed`: tool name is `write_db`, `update_record`, `insert`, `modify`, or starts with `set_` / `save_`
- `high blast-radius combination`: agent has both a "read" tool (query, get, fetch, search, lookup, read, list, find) AND any write tool

## MCP servers

Detector: `src/ai_surface/detectors/mcp_servers.py`

Scans for both **configured** MCP servers (pointing to external endpoints) and **source-resident** in-house MCP servers (custom server code).

### Configured MCP servers

| File / pattern | Where it appears |
|---|---|
| `.mcp.json` | Repository root, common locations |
| `mcp_servers/` directory | Common organizational pattern |
| `claude_desktop_config.json` | Claude Desktop config |

Extracts: server name, command or URL, tool catalog, capabilities.

### In-house MCP server code

| Pattern | Language |
|---|---|
| `FastMCP()` constructor | Python |
| `mcp.Server()` constructor | Python |
| `Server(...)` from `@modelcontextprotocol/sdk` | JavaScript / TypeScript |

Extracts: tool registrations (`@tool`, `server.tool(...)`, etc.).

### Risk indicators

- `broad permissions`: MCP server has admin, write, or delete capabilities declared
- `in-house MCP server (custom code, audit recommended)`: flagged on every source-resident server, signaling to reviewers that custom code needs deeper inspection
- `financial action exposed`, `destructive action exposed`, `messaging action exposed`, `database write exposed`: applied to MCP server tool catalogs using the same vocabulary as agents

## AI provider env keys

Detector: `src/ai_surface/detectors/env_keys.py`

Scans `.env`, `.env.example`, `.env.local`, etc. for AI provider API key **names**. **Never reads the values.**

### Keys recognized

- `OPENAI_API_KEY`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`
- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_*`
- `AWS_BEDROCK_*` (when set explicitly; usually relies on standard AWS credentials)
- `GOOGLE_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`
- `VERTEX_AI_*`
- `TOGETHER_API_KEY`
- `MISTRAL_API_KEY`
- `COHERE_API_KEY`
- `REPLICATE_API_TOKEN`
- `GROQ_API_KEY`
- `LANGSMITH_API_KEY`, `LANGCHAIN_API_KEY` (observability)
- `HELICONE_API_KEY`, `ARIZE_API_KEY`, `PORTKEY_API_KEY` (gateway / observability)
- `WANDB_API_KEY` (W&B for AI experiment tracking)

### Risk indicators

- `multiple AI provider keys present`: when more than one provider's keys are configured (suggests multi-vendor AI architecture)
- `observability/tracing key present (production telemetry to third party)`: when LangSmith, Helicone, Arize, or similar telemetry keys are present (signals where production AI data flows)

## Model gateways and AI infrastructure

Detector: `src/ai_surface/detectors/model_gateways.py`

Scans for model gateway configs, self-hosted LLM runtimes, and AI infrastructure declarations in code, config files, IaC, and Kubernetes manifests.

### Gateways

| Tool | What we look for |
|---|---|
| **LiteLLM** proxy | `litellm_config.yaml`, `litellm` Python imports in proxy contexts |
| **Portkey** | `portkey-ai` SDK, Portkey config files |
| **Helicone** | Helicone SDK setup, observability instrumentation |
| **Cloudflare AI Gateway** | Cloudflare AI Gateway endpoint URLs, TOML configs |

### Self-hosted runtimes

| Pattern | Where |
|---|---|
| **Ollama** | Kubernetes deployments with `ollama/ollama` image, `docker-compose.yaml` with ollama service |
| **vLLM** | Kubernetes deployments with `vllm/vllm-openai` image, vLLM Python serve scripts |
| **Text Generation Inference (TGI)** | Kubernetes deployments with `ghcr.io/huggingface/text-generation-inference` |
| **LocalAI** | LocalAI container images in Kubernetes / docker-compose |

### IaC / cloud AI infrastructure

| Pattern | Source |
|---|---|
| Bedrock provisioned throughput | Terraform `aws_bedrock_*` resources |
| Bedrock custom models | Terraform `aws_bedrock_custom_model` resources |
| Sagemaker endpoints (LLM-tagged) | Terraform `aws_sagemaker_endpoint` with LLM-named models |

### Risk indicators

- `multi-model routing layer (production traffic flows through this)`: gateway config detected, signaling where AI traffic concentrates
- `self-hosted LLM runtime (operational responsibility on the team)`: self-hosted ollama/vLLM/TGI detected
- `high-cost AI infrastructure (billing exposure)`: Bedrock provisioned throughput or large GPU instances

## Risk indicator vocabulary

The complete list of 13 risk indicators v0.5 can emit:

| Indicator | Category | What it means |
|---|---|---|
| `broad permissions` | MCP | MCP server with admin/write/delete capabilities |
| `in-house MCP server (custom code, audit recommended)` | MCP | Custom MCP server code; deeper review warranted |
| `financial action exposed` | Agent / MCP | refund / payment / charge tool present |
| `destructive action exposed` | Agent / MCP | delete / drop / truncate tool present |
| `messaging action exposed` | Agent / MCP | send_email / send_slack / send_sms tool present |
| `database write exposed` | Agent / MCP | DB mutation tool present |
| `high blast-radius combination` | Agent | Agent holds both read AND destructive/financial tools |
| `non-literal data flows into LLM call` | LLM SDK | Variable input to messages= or prompt= |
| `multiple AI provider keys present` | Env keys | More than one provider configured |
| `observability/tracing key present` | Env keys | LangSmith / Helicone / Arize key configured |
| `multi-model routing layer` | Gateway | Production traffic flows through gateway |
| `self-hosted LLM runtime` | Infra | Team operates the LLM server itself |
| `high-cost AI infrastructure` | Infra | Bedrock provisioned throughput or large GPU instances |

## Known limitations

`ai-surface` v0.5 is honest about what it does and doesn't see:

**Detection limitations:**

- Regex-based tool resolution (AST in v0.6 for higher precision)
- Single-document YAML parsing only (v0.6 adds multi-document)
- Cross-file dataflow is approximate; we use file-local heuristics for now
- We don't detect prompt templates, RAG pipelines, fine-tuning code, eval pipelines, or AI guardrails as separate categories (future specialist tools cover these)

**By-design exclusions:**

- Local developer AI tools (Cursor, Claude Code, Copilot) are NOT in scope. This tool is about AI in shipping application code.
- Runtime behavior monitoring is NOT in scope. Use Helicone, LangSmith, Arize, or Phoenix for that.
- Prompt-injection or LLM behavior testing is NOT in scope. See the APIsec platform for runtime exploit validation.
- Live cluster scanning is NOT in scope today (planned for v0.7).

For coverage gaps not on this list, [file a false-negative issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-negative.yml).

For false positives where we flag something incorrectly, [file a false-positive issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-positive.yml).

---

For deeper questions about how detection works internally, see [docs/ARCHITECTURE.md](ARCHITECTURE.md).
