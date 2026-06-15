# ai-surface language support

What ai-surface detects, by language. Two things to know up front:

1. **Configuration, keys, and specs are language-agnostic.** Provider keys,
   MCP configs, OpenAPI/API specs, model-gateway configs, and AI infrastructure
   (IaC) are detected on **any stack**, so every repo gets baseline coverage
   regardless of language.
2. **Code-level detection** (LLM call sites, agents and their tools, in-house
   MCP and gateway source) is **deepest on Python and TypeScript/JavaScript**.

## Matrix

| AI component (detector) | Python | TS / JS | Java | Other (Go, Rust, C#, Ruby...) | Any stack (config / spec / env) |
|---|:--:|:--:|:--:|:--:|:--:|
| Provider keys (`env_keys`) | n/a | n/a | n/a | n/a | yes (.env, env files) |
| LLM call sites (`llm_sdks`) | yes | yes | no | no | n/a |
| AI agents + tools (`agent_frameworks`) | yes | yes | no | no | n/a |
| MCP servers (`mcp_audit`) | yes (source) | yes (source) | no | no | yes (.mcp.json / mcp.json / yaml) |
| API endpoints (`api_endpoints`) | yes | yes | yes | no | yes (OpenAPI / Swagger specs) |
| Model gateways (`model_gateways`) | yes (source) | yes (source) | no | no | yes (config: yaml / json / toml) |
| AI infrastructure (`ai_infra`) | n/a | n/a | n/a | n/a | yes (yaml, Terraform .tf/.tfvars) |

Code-level extensions: Python `.py`; TS/JS `.ts .tsx .js .jsx .mjs .cjs`; Java `.java` (API routes only).

## What this means per stack

- **Any repo (Java, Go, C#, Rust, Ruby, ...):** you still get provider keys, MCP configs, OpenAPI/API specs, model-gateway configs, and AI infrastructure. ai-surface is never blind.
- **Python and TS/JS repos:** you additionally get LLM call sites, AI agents (with tool extraction), in-house MCP source, and gateway source.
- **Java repos:** API endpoint (route) detection on top of the any-stack baseline.

## Cross-cutting risk checks follow the component

The audits and governance mapping are not separate language features; they apply
wherever the component is detected:

- **Agent audits** (excessive capability, financial / destructive action, high
  blast-radius, PII-into-LLM) run for **Python and TS/JS** agents.
- **Human-oversight** and **observability** checks run for the autonomous
  execution surfaces (agents, MCP) in **Python and TS/JS**.
- **Secret detection** runs in any MCP config (any stack).
- **BOLA-candidate** detection runs wherever API endpoints are detected (Python,
  TS/JS, Java, and OpenAPI specs).
- **OWASP + EU AI Act / NIST / ISO mapping** applies to every finding, any stack.

## Detected frameworks (code-level)

- **LLM SDKs:** OpenAI, Anthropic, AWS Bedrock, and others (Python + TS/JS).
- **Agents:** LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, Haystack,
  Semantic Kernel, Pydantic AI, AWS Strands (Python); LangChain.js, LangGraph.js,
  Vercel AI SDK, Mastra, OpenAI Agents, LlamaIndex.ts (TS/JS).

## Roadmap

Code-level agent and LLM detection for **Java, Go, C#, Rust, and Ruby** is not
yet implemented; those stacks get the any-stack baseline today. Java API-route
detection already exists. Priority order is set by where AI code actually lives
(Python and TS/JS first, which is now covered).
