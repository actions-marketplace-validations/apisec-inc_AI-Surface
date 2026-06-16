# Detector Coverage Matrix

Complete list of what each `ai-surface` detector finds, the patterns it matches, and the risk indicators it can raise.

This document is the **detection contract**. If you're evaluating whether `ai-surface` will see your AI surfaces, scan this list. If something's missing, [file a false-negative issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-negative.yml) with a minimal reproducer.

## Contents

- [Agent frameworks](#agent-frameworks)
- [MCP servers](#mcp-servers)
- [Vector stores and RAG](#vector-stores-and-rag)
- [LLM SDK call sites](#llm-sdk-call-sites)
- [API endpoints](#api-endpoints)
- [AI provider env keys](#ai-provider-env-keys)
- [Model gateways](#model-gateways)
- [AI infrastructure](#ai-infrastructure)
- [Risk indicator vocabulary](#risk-indicator-vocabulary)
- [Governance mapping](#governance-mapping)
- [Known limitations](#known-limitations)

The eight detector categories: **agent frameworks**, **MCP servers**, **vector stores / RAG**, **LLM SDK call sites**, **API endpoints**, **AI provider env keys**, **model gateways**, and **AI infrastructure**. Configuration, keys, and specs are detected on any stack; deep code-level detection is strongest on Python and TypeScript/JavaScript (see [LANGUAGE_SUPPORT.md](LANGUAGE_SUPPORT.md)).

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

- `non-literal data flows into LLM call`: variable references in `messages=` or `prompt=` kwargs (regex-based today; AST for higher precision is a roadmap item)

## API endpoints

Detector: `src/ai_surface/detectors/api_endpoints.py`

Scans OpenAPI / Swagger specs and framework route definitions for the HTTP surface that fronts the application (the API the AI layer, and everyone else, is reached through). Selectable with `--categories api`.

### Sources detected

| Source | What we read |
|---|---|
| **OpenAPI / Swagger** | every `path` + method pair in `openapi.yaml` / `swagger.json` (and JSON variants) |
| **FastAPI / Starlette** | `@app.get/post/...`, `APIRouter` routes (with `prefix=` resolution) |
| **Flask** | `@app.route(...)`, blueprint routes |
| **Express** | `app.get/post/...`, `router.<verb>(...)` |
| **Spring** | `@GetMapping` / `@PostMapping` / `@RequestMapping` (Java) |
| **Django** | `urlpatterns` `path()` / `re_path()` |

Captures method, path, framework, and detected auth style (bearer, basic, api-key, none).

### Risk indicators

- `object-id in path (BOLA candidate)`: the route carries an object-id segment (`{id}`, `:id`, `<int:id>`), the structural precondition for Broken Object-Level Authorization. This is the single most common finding on real apps.

## Agent frameworks

Detector: `src/ai_surface/detectors/agent_frameworks.py`

Scans Python and JS/TS source for agent framework imports, named agent definitions, and per-agent tool inventories. Agents defined only inside test/spec files are excluded (they are not part of an application's real AI surface).

### Frameworks detected (Python)

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

### Frameworks detected (JavaScript / TypeScript)

| Framework | Import roots | Specific pattern |
|---|---|---|
| **LangChain.js** | `langchain`, `@langchain` | `AgentExecutor`, `createToolCallingAgent`, `initializeAgentExecutorWithOptions` |
| **LangGraph.js** | `@langchain/langgraph` | `new StateGraph()`, `createReactAgent()` |
| **Vercel AI SDK** | `ai`, `@ai-sdk` | `generateText({tools})`, `streamText({tools})` (only when tools are wired) |
| **Mastra** | `@mastra/core`, `@mastra` | `new Agent({...})`, `createAgent()` |
| **OpenAI Agents** | `@openai/agents` | `new Agent({...})` |
| **LlamaIndex.ts** | `llamaindex` | `OpenAIAgent`, `ReActAgent` |

### Tool extraction methods

For each named agent, `ai-surface` extracts tool inventories from (in priority order): the `tools=[...]` block inside the constructor; a `tools=<var>` kwarg resolved to an in-file list variable; the nearest `tools=[...]` block in the same file; `@tool`-decorated functions; Anthropic-shape `tools=[{"name": "x"}]` dict literals; and, for JS/TS, the Vercel-style `tools: { name: tool({...}) }` object keys. Tools built by a factory call (`tools=make_tools()`) need cross-file dataflow and are a roadmap item.

### Risk indicators and audit flags

- `financial action exposed`: tool name contains `refund`, `payment(s)`, `charge(s)`, `transfer`, `withdraw`, `payout(s)`, `invoice(s)`
- `destructive action exposed`: tool name contains `delete`, `drop`, `truncate`, `remove`, `purge`, `destroy`
- `messaging action exposed`: `send_email`, `send_message`, `send_slack`, `send_sms`, `post_to_*`
- `database write exposed`: `write_db`, `update_record`, `insert`, `modify`, `set_*`, `save_*`
- `high blast-radius combination`: agent has both a read tool AND any write tool
- `pii-to-llm` (audit): customer PII (email / address / SSN patterns) interpolated into a prompt the agent sends (maps to LLM02 / EU Art. 10)
- `no-human-oversight` (audit): a financial / destructive / high-blast-radius agent with no approval gate on its path (EU Art. 14)
- `no-observability` (audit): an agent surface in a repo that wires no AI tracing anywhere (EU Art. 12 / NIST MEASURE 3 / ISO A.6.2.6)

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
- `secrets-in-env` / `secrets-detected` (audit): a live secret in the MCP env block or config (reported by NAME and TYPE only, values redacted; LLM02 / EU Art. 15)
- `unverified-source` (audit): the server is not found in a known registry (LLM03 / ISO A.10)
- `no-human-oversight`, `no-observability` (audit): same semantics as for agents

## Vector stores and RAG

Detector: `src/ai_surface/detectors/vector_rag.py`

Scans Python, JS/TS, and `.sql` for vector databases and retrieval-augmented-generation pipelines. RAG is the dominant enterprise AI pattern, so the retrieval layer is a first-class surface.

### Stores detected

| Store | Type | Matched on |
|---|---|---|
| **Pinecone** | managed | `pinecone` import, `@pinecone-database/pinecone`, `PINECONE_API_KEY`, LangChain wrapper |
| **Weaviate** | managed | `weaviate` import, `weaviate-client`, LangChain wrapper |
| **Marqo** | managed | `marqo` import, LangChain wrapper |
| **Chroma** | self-hosted | `chromadb` import, LangChain wrapper |
| **Qdrant** | self-hosted | `qdrant_client`, `@qdrant/js-client-rest`, `QdrantClient(`, LangChain wrapper |
| **Milvus** | self-hosted | `pymilvus`, `@zilliz/milvus2-sdk-node`, LangChain wrapper |
| **pgvector** | self-hosted | `pgvector` import, SQL `CREATE EXTENSION vector` / `USING ivfflat\|hnsw`, `langchain_postgres`, `PGVector` |
| **Elasticsearch (vector)** | self-hosted | `ElasticsearchStore`, `dense_vector`, `langchain_elasticsearch` |
| **OpenSearch (vector)** | self-hosted | `OpenSearchVectorSearch`, `knn_vector`, LangChain wrapper |
| **Vespa** | self-hosted | `vespa` / `pyvespa` import, `VespaStore` |
| **Redis (vector)** | self-hosted | `RedisVectorStore`, `RediSearch`, LangChain wrapper |
| **FAISS** | embedded | `faiss` import, `faiss-node`, LangChain wrapper |
| **LanceDB** | embedded | `lancedb` import, `@lancedb/lancedb`, `vectordb`, LangChain wrapper |

Search engines (Elasticsearch / OpenSearch / Redis) are matched only on vector-specific signals, so plain logging or search use is not mis-flagged.

### RAG pipelines detected

| Framework | Matched on |
|---|---|
| **LangChain** | `langchain...vectorstores`, `.as_retriever()` / `.asRetriever()`, `RetrievalQA`, `VectorStoreRetriever` |
| **LlamaIndex** | `VectorStoreIndex`, `.as_query_engine()`, `VectorIndexRetriever` |

### Risk indicators

- `managed vector store (indexed data and embeddings leave your environment)`: a cloud/SaaS store
- `retrieved content reaches the model (retrieval-augmented generation)`: a RAG retriever construct is present
- `application data embedded for retrieval`: embeddings (`OpenAIEmbeddings`, `embed_query`, `text-embedding-*`, etc.) detected
- `ingests external content (RAG poisoning surface)`: an external loader (`WebBaseLoader`, `RecursiveUrlLoader`, `SitemapLoader`, `FireCrawlLoader`, etc.) feeds the index

All vector/RAG findings map to OWASP LLM08 and the EU Art. 10 / ISO A.7 data-governance clauses.

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

## Model gateways

Detector: `src/ai_surface/detectors/model_gateways.py`

Scans for model gateway / routing layers that sit in front of LLM providers, from config files and source-level imports / URL references.

| Tool | What we look for |
|---|---|
| **LiteLLM** proxy | `litellm` proxy `config.yaml` (`model_list` + `litellm_params`), `litellm.proxy` Python imports |
| **Portkey** | `portkey-ai` SDK, `portkey-config.json` |
| **Helicone** | Helicone proxy URLs, `HELICONE_API_KEY`, `Helicone-*` headers |
| **Cloudflare AI Gateway** | `gateway.ai.cloudflare.com` URLs, Workers AI bindings |
| **OpenRouter** | `openrouter.ai/api` URLs, `OPENROUTER_API_KEY` |

### Risk indicators

- `multi-model routing layer (production traffic flows through this)`: gateway config detected, signaling where AI traffic concentrates

## AI infrastructure

Detector: `src/ai_surface/detectors/ai_infra.py`

Scans for self-hosted AI runtimes and managed AI cloud resources declared in deployment specs and infrastructure-as-code. Selectable with `--categories infra`.

### Self-hosted runtimes (Kubernetes / Helm / docker-compose / Dockerfiles)

Workload kinds recognised in K8s manifests: `Deployment`, `StatefulSet`, `DaemonSet`, `Pod`, `Job`, `CronJob`, `ReplicaSet`, Argo `Rollout`.

| Pattern | Where |
|---|---|
| **Ollama** | K8s / Helm / compose image `ollama/ollama`; Dockerfile `FROM` or `ollama serve` |
| **vLLM** | image `vllm/vllm-openai`; Dockerfile `FROM` or `vllm serve` / `vllm.entrypoints` |
| **Text Generation Inference (TGI)** | image `huggingface/text-generation-inference`; `text-generation-launcher` |
| **SGLang / Triton / llama.cpp / LocalAI / Aphrodite / Infinity / OpenLLM / NVIDIA NIM / Ray LLM / xinference / text-embeddings-inference** | container images in K8s / Helm / compose, or AI-runtime Dockerfiles |

Dockerfiles (`Dockerfile`, `*.Dockerfile`, `Containerfile`) match on the `FROM` base image first, then fall back to serve commands (shell or JSON-array exec form).

### IaC / cloud AI infrastructure

| Pattern | Source |
|---|---|
| Bedrock provisioned throughput | Terraform `aws_bedrock_provisioned_model_throughput` |
| Bedrock custom models | Terraform `aws_bedrock_custom_model` |
| SageMaker endpoints (LLM-tagged) | Terraform `aws_sagemaker_endpoint` with LLM-named models |
| Vertex AI endpoints | Terraform `google_vertex_ai_endpoint` |

### Risk indicators

- `self-hosted LLM runtime (operational responsibility on the team)`: self-hosted runtime detected in a manifest, compose file, or Dockerfile
- `high-cost AI infrastructure (billing exposure)`: managed AI compute such as Bedrock provisioned throughput or a SageMaker LLM endpoint

## Risk indicator vocabulary

Severity-free inventory indicators (for human review):

| Indicator | Category | What it means |
|---|---|---|
| `broad permissions` | MCP | MCP server with admin/write/delete capabilities |
| `in-house MCP server` | MCP | Custom MCP server code; deeper review warranted |
| `financial action exposed` | Agent / MCP | refund / payment / charge / payout tool present |
| `destructive action exposed` | Agent / MCP | delete / drop / truncate tool present |
| `messaging action exposed` | Agent / MCP | send_email / send_slack / send_sms tool present |
| `database write exposed` | Agent / MCP | DB mutation tool present |
| `high blast-radius combination` | Agent | Agent holds both read AND destructive/financial tools |
| `object-id in path (BOLA candidate)` | API | Route with an object-id segment |
| `managed vector store` | Vector/RAG | Indexed data and embeddings leave the environment |
| `ingests external content` | Vector/RAG | RAG poisoning surface (external loader) |
| `non-literal data flows into LLM call` | LLM SDK | Variable input to messages= or prompt= |
| `multiple AI provider keys present` | Env keys | More than one provider configured |
| `multi-model routing layer` | Gateway | Production traffic flows through gateway |
| `self-hosted LLM runtime` | Infra | Team operates the LLM server itself |
| `high-cost AI infrastructure` | Infra | Bedrock provisioned throughput or large GPU instances |

Structured **audit flags** (carry a severity, OWASP id, governance clauses, and remediation): `secrets-detected`, `secrets-in-env`, `financial-action`, `destructive-action`, `high-blast-radius`, `no-human-oversight`, `no-observability`, `pii-to-llm`, `unverified-source`, `remote-mcp`, plus capability flags (shell / filesystem / database / network). See [COMPLIANCE.md](COMPLIANCE.md) for the full flag-to-clause mapping.

## Governance mapping

Every audited finding maps to the OWASP LLM Top 10 and to the specific EU AI Act / NIST AI RMF / ISO 42001 clauses it evidences. The full mapping tables live in [**COMPLIANCE.md**](COMPLIANCE.md). The mappings appear as badges in the `--ui`, as a `standards` array on each risk flag in the JSON output, and as component properties in the CycloneDX AI-BOM.

## Known limitations

`ai-surface` is honest about what it does and doesn't see:

**Detection limitations:**

- Regex/AST-light tool resolution; tools built by factory functions across files are not yet resolved (AST/dataflow is the top roadmap item). Treat the map as a strong floor, not a proof of completeness.
- Cross-file dataflow is approximate; we use file-local heuristics for now.
- Code-level agent / LLM detection covers Python and TS/JS; other stacks get the config / spec / key baseline (see [LANGUAGE_SUPPORT.md](LANGUAGE_SUPPORT.md)).

**By-design exclusions:**

- Local developer AI tools (Cursor, Claude Code, Copilot) are NOT in scope. This tool is about AI in shipping application code.
- Runtime behavior monitoring is NOT in scope. Use Helicone, LangSmith, Arize, or Phoenix for that.
- Prompt-injection, jailbreak, bias, or accuracy / model-behavior testing is NOT in scope, permanently and by design. See the APIsec platform for runtime exploit validation.
- Live cluster scanning is NOT in scope today (on the roadmap).

For coverage gaps not on this list, [file a false-negative issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-negative.yml).

For false positives where we flag something incorrectly, [file a false-positive issue](https://github.com/apisec-inc/AI-Surface/issues/new?template=false-positive.yml).

---

For deeper questions about how detection works internally, see [docs/ARCHITECTURE.md](ARCHITECTURE.md).
