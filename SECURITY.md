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

## What we defend against

Because the scanner regularly reads **attacker-controlled source code** (the whole point is scanning a PR's contents), the tool ships with explicit defences for the threats that follow from that posture:

- **Supply-chain via `pull_request_target`** — the GitHub Action refuses to run under the `pull_request_target` event. That event runs with repo write secrets against attacker-checked-out PR code and is the canonical pwn-request pattern. Use the `pull_request` event instead.
- **Symlink-based path escape** — the file walker never follows symlinks. `os.lstat` is used for all size accounting and `read_text_safe` rejects any path where `S_ISLNK` is true. A symlink to `/etc/shadow` or `/dev/zero` cannot be read or counted.
- **Denial-of-service via giant trees** — hard caps on file count (`MAX_FILES = 250,000`) and cumulative size (`MAX_TOTAL_BYTES = 5 GiB`) bound the work per traversal. Per-file reads are capped at 5 MB with the read itself re-bounded at the API call (defence-in-depth against TOCTOU races between stat and open).
- **Regex denial-of-service (ReDoS)** — detector regexes have been hardened against catastrophic backtracking. The agent-framework patterns use bracket-balanced body extraction with per-call and per-file caps, not unbounded lazy quantifiers. A 5 MB file of adversarial input that previously stalled the scanner now completes in seconds; a regression test pins this.
- **Output injection into PR comments** — snippets are wrapped in length-aware code fences that defeat ``` break-out. Surface names, file paths, permissions, and risk indicators are sanitised to strip control characters, angle brackets, backticks, and leading markdown structural characters before any heading or bullet is rendered.
- **Local filesystem-path disclosure** — `Report.scan_root` is the basename of the scanned directory, not the resolved absolute path. Evidence paths that resolve outside the scan root render as `<outside-root>/{basename}`. Reports are routinely committed to git or posted to public PRs; we keep the user's home directory, employer name, and internal mount layout out of them.

## Coordinated disclosure

We follow standard coordinated disclosure: we will work with you on a timeline for public disclosure that gives users time to upgrade. Default is 90 days from initial report or until a fix is shipped, whichever comes first.
