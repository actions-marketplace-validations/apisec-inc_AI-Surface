# State of AI Surface

A static `ai-surface` scan of **19 of the most popular open-source AI projects on
GitHub** (about 941k combined stars). Scan only: each repo was cloned shallow,
scanned, and deleted. No application was run, no code left the host. Results
reflect three detector efficacy fixes made during this sweep (see the bottom of
this page).

![State of AI Surface report](images/state-of-ai-surface.png)

The set splits into **12 applications** and **7 frameworks/libraries**, reported
separately: framework repos ship every integration as a code path, so their
component counts are not comparable to applications. Headline stats below are
over the 12 applications only.

## Headline (12 applications, category presence)

| Signal | Apps |
|---|---|
| Ship AI agents | **83%** |
| Have a vector store / RAG layer | **83%** |
| Expose API endpoints | **83%** |
| Have BOLA candidate endpoints | **67%** |
| Expose MCP servers | **42%** |
| Run an agent/MCP surface with no observability wired | **33%** |
| Interpolate PII into prompts | **17%** |
| **Trip at least one risk and one governance rule** | **100% (12/12)** |

Agents and RAG are effectively universal. The bulk of the attack surface is still
ordinary REST, and it is BOLA-dense. Every single application maps to at least
one AI-governance framework.

## Compliance frameworks tripped

| Framework | Apps |
|---|---|
| OWASP LLM Top 10 | 10/12 |
| ISO/IEC 42001 | 9/12 |
| EU AI Act | 5/12 |
| NIST AI RMF | 4/12 |

The two apps that do not trip OWASP are tiny starter repos whose only finding is
`no-observability`, a record-keeping control that maps to EU Art. 12 / ISO
A.6.2.6 / NIST MEASURE 3 rather than an OWASP item.

## Per-application appendix

Columns: agents, MCP servers, vector/RAG findings, API endpoints, and whether the
app trips BOLA / observability-gap / PII-into-prompt.

| Application | Stars | Agents | MCP | Vec | APIs | BOLA | No-obs | PII |
|---|--:|--:|--:|--:|--:|:--:|:--:|:--:|
| autogpt | 185k | 1 | 0 | 2 | 480 | yes | - | - |
| dify | 145.3k | 2 | 0 | 7 | 748 | yes | - | yes |
| ragflow | 82.8k | 0 | 1 | 1 | 318 | yes | - | - |
| privategpt | 57.3k | 1 | 0 | 2 | 68 | yes | - | - |
| khoj | 35.1k | 2 | 0 | 1 | 84 | yes | yes | yes |
| continue | 33.7k | 1 | 14 | 1 | 18 | - | - | - |
| danswer | 30.3k | 3 | 9 | 2 | 524 | yes | - | - |
| gpt-researcher | 27.7k | 3 | 1 | 2 | 16 | yes | - | - |
| verba | 7.7k | 1 | 0 | 1 | 25 | - | yes | - |
| supabase-ai-chatbot | 813 | 1 | 0 | 0 | 0 | - | yes | - |
| ai-sdk-reasoning-starter | 182 | 1 | 0 | 0 | 0 | - | yes | - |
| ragbot | 32 | 0 | 3 | 1 | 51 | yes | - | - |

### Frameworks / libraries (counts not comparable to apps)

| Project | Stars | Agents | MCP | Vec | APIs |
|---|--:|--:|--:|--:|--:|
| mcp-servers | 87.3k | 0 | 50 | 0 | 5 |
| autogen | 59k | 51 | 2 | 1 | 35 |
| crewai | 53.6k | 15 | 1 | 4 | 27 |
| llama_index | 50.2k | 4 | 3 | 14 | 22 |
| langgraph | 34.9k | 4 | 0 | 2 | 0 |
| mastra | 25.1k | 183 | 28 | 7 | 65 |
| vercel-ai | 24.9k | 454 | 31 | 0 | 27 |

## Honesty notes

**These numbers are a floor, not a ceiling.** Tool resolution is regex/AST-light
today, so the `financial-action` / `destructive-action` / `no-human-oversight`
flags under-fire on large platforms that build agent tools via factory functions.
The real governance footprint is at least what is shown here, often more.
Category-presence and compliance-framework mapping are the reliable signals;
per-component raw counts are indicative only.

**Efficacy fixes made during this sweep** (the value of running on real code):

1. Test-file false positives removed from agent counts (agents defined only
   inside unit tests are not part of an app's real AI surface).
2. Observability was no longer credited from dependency manifests or lockfiles. A
   transitive `langsmith` dependency of `langchain` had been making every
   langchain repo look "observed"; the gap moved to a believable 33% after the
   fix.
3. A minified-bundle false positive (the word "weave" inside Next.js build output)
   was removed.

Methodology: shallow clone, `ai-surface scan <repo> --output json`, delete. The
scanner never executed project code and made no network calls.
