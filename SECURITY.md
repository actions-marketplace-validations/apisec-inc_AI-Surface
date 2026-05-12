# Security Policy

## Reporting a vulnerability

If you discover a security issue in `ai-surface`, please email **security@apisec.ai** rather than filing a public GitHub issue.

Include:
- A description of the issue
- Steps to reproduce, or a minimal proof-of-concept
- The impact you believe it has
- Your suggested fix, if any

We'll acknowledge receipt within **2 business days** and aim to address valid reports within **30 days** of confirmation. Critical issues that allow remote code execution or arbitrary file disclosure will be prioritized.

## Scope

In scope:
- Bugs in `ai-surface` itself that allow unintended file access, code execution, or data exfiltration
- Vulnerabilities in the GitHub Action wrapper that could compromise customer repositories or workflow secrets
- Output-injection issues (e.g., a crafted source file that breaks PR comment rendering or shell escapes)

Out of scope:
- Findings about your own AI surfaces detected by the tool (those are product output, not vulnerabilities)
- Issues in upstream dependencies — report those to the dependency maintainers
- Social-engineering attacks on the project's maintainers

## What `ai-surface` does and does not do

`ai-surface` is a **static source-code analyzer**. It:
- Reads files from the filesystem within the directory you scan
- Reports findings to stdout, a JSON file, a markdown file, or a PR comment
- Does not connect to any external service unless you explicitly invoke the GitHub Action (which posts a comment via the GitHub API using a token you provide)
- Does not transmit your code, findings, or any other data to APIsec or third parties
- Does not require authentication, credentials, or network access during a normal scan

If you believe `ai-surface` is doing any of these things contrary to its design, that itself is a security issue worth reporting.

## Coordinated disclosure

We follow standard coordinated disclosure: we will work with you on a timeline for public disclosure that gives users time to upgrade. Default is 90 days from initial report or until a fix is shipped, whichever comes first.
