# Examples

Hands-on examples for `ai-surface`. Use them to see the tool in action, model your own integration, or copy CI config straight into your repo.

## Contents

| Folder | What's in it |
|---|---|
| **[`demo-app/`](demo-app/)** | A small synthetic codebase that exercises every detector category. Scan it to see what a rich findings report looks like. |
| **[`sample-outputs/`](sample-outputs/)** | Captured output from scanning `demo-app/` in every format: terminal, JSON, markdown, PR comment. |
| **[`workflows/`](workflows/)** | GitHub Actions YAML for several common patterns: basic, blocking, custom severity thresholds, on-main inventory refresh. |
| **[`integrations/`](integrations/)** | Non-GitHub CI examples: GitLab CI, CircleCI, pre-commit hook. |

## Try it on the demo app

```bash
# From the ai-surface repo root
ai-surface scan examples/demo-app
```

Expected: **11 AI surfaces, 13 risk indicators, 5 detectors**.

The demo app covers:

| Category | What's there |
|---|---|
| LLM SDKs | OpenAI, Anthropic, AWS Bedrock (via Strands) |
| Agent frameworks | LangChain support agent, AWS Strands triage agent |
| MCP servers | 2 configured (github, stripe), 1 in-house (orders) |
| AI provider env keys | OpenAI, Anthropic, LangSmith, Helicone |
| Model gateways | LiteLLM with 3-provider fallback chain |

## Pick a workflow

| You want | Use |
|---|---|
| The simplest possible setup | [`workflows/basic.yml`](workflows/basic.yml) |
| To block PRs on any risk | [`workflows/fail-on-risk.yml`](workflows/fail-on-risk.yml) |
| To block only on high-severity risks | [`workflows/custom-risk-threshold.yml`](workflows/custom-risk-threshold.yml) |
| To auto-refresh the inventory on main | [`workflows/scan-on-main.yml`](workflows/scan-on-main.yml) |

## Pick an integration

| Your CI | Use |
|---|---|
| GitLab | [`integrations/gitlab-ci.yml`](integrations/gitlab-ci.yml) |
| CircleCI | [`integrations/circleci.yml`](integrations/circleci.yml) |
| Local pre-commit hook | [`integrations/pre-commit-hook.sh`](integrations/pre-commit-hook.sh) |

## What if I want something else?

Open an [issue](https://github.com/apisec-inc/AI-Surface/issues) and we'll either help you wire it up or add an example here.
