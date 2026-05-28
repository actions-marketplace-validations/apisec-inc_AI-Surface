# Privacy and Data Handling

This document is the **data-handling contract** for `ai-surface`. It exists for security and compliance reviewers who need a clear answer to "what does this tool do with our code and data?" If you are running `ai-surface` through a procurement or security-questionnaire process, this is the page to cite.

For the threat-model side (what attacker shapes the tool defends against), see [`SECURITY.md`](../SECURITY.md). The two docs are complementary.

## TL;DR

`ai-surface` is a static source-code analyzer. It reads files from the directory you point it at, runs regex and YAML based detectors over them, and writes a report. The tool does not execute your code, does not read secret values, does not make a network call during a CLI scan, and does not send data to APIsec or any third party. The only network operation in the entire project is the GitHub Action wrapper posting a PR comment back to your own repository using a token your workflow provides.

If you observe `ai-surface` doing anything outside of this contract, that is itself a security issue and we want to hear about it (see [`SECURITY.md`](../SECURITY.md)).

## What `ai-surface` reads

| Data | Source | Notes |
|---|---|---|
| File contents (text) | Files inside the directory passed to `scan` | Honours the **root** `.gitignore` plus a hard skip-list for build dirs (`node_modules`, `.venv`, `dist`, etc.). Nested per-directory `.gitignore` files, `.git/info/exclude`, and the global excludesfile are NOT consulted (intentional, documented). |
| File metadata (size, type) | `os.lstat` on each file | Used for caps, never to follow symlinks. Symlinks are explicitly rejected. |
| Configuration files | `.mcp.json`, `.env`, `*.env`, `litellm` configs, k8s manifests, Helm values, Terraform, Dockerfiles, docker-compose | Standard detection targets. |
| Source files | `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.toml`, `.json` (depending on detector) | Read as text, never executed. |
| `.env` env-key NAMES | Lines matching `KEY=...` patterns | The **name** of each environment variable is matched against the provider key catalogue. **The value after `=` is never captured, logged, or returned.** Any snippet that contains a matched key is rewritten to `KEY=<redacted>` before it leaves the env-key detector. |

## What `ai-surface` writes

Always under your control. The tool writes only what you explicitly ask for.

| Output | When | Where |
|---|---|---|
| Terminal report | Default `scan` | stdout |
| JSON report | `--output json` | stdout (or a file if you redirect) |
| Markdown report | `--output markdown` | stdout (or a file if you redirect) |
| `.ai-inventory.md` | `--write-inventory` | The scan root |
| `.ai-surface-baseline.json` | `--update-baseline` | The scan root (or a custom path via `--baseline-file`) |
| Quiet summary line | `--quiet` | stdout |
| GitHub PR comment | GitHub Action only, when `comment-on-pr: 'true'` | Your own repository, via the GitHub API, using the workflow's `GITHUB_TOKEN` you provided |

The tool does not write to any temporary or hidden location of its own. No `~/.cache`, no `/tmp` files, no `~/.ai-surface/` directory, no shell history modification, no clipboard interaction.

## Network access

| Mode | Network calls |
|---|---|
| `ai-surface scan ...` (CLI, any flags) | **None.** Runs entirely offline. Can be executed on a host with no network interface, in an air-gapped container, or behind a strict firewall. |
| `ai-surface compare ...` | **None.** Reads two local JSON files. |
| `ai-surface version` | **None.** Prints a version string. |
| GitHub Action wrapper | **One outbound HTTPS call**, to `api.github.com`, to post or update a PR comment. Uses the `GITHUB_TOKEN` the workflow passes in. No other endpoint is contacted. |

The tool does not emit telemetry of any kind. There is no anonymous usage ping, no update check, no remote configuration fetch, and no opt-in option to enable any of these later. The code path simply does not exist in the project, so there is nothing to configure on or off.

You can verify this yourself with `strace -e trace=network`, `tcpdump`, or by running in a container with `--network=none`. Each of these will show zero network activity for a `scan` invocation.

## What `ai-surface` does NOT do

This list is intentionally explicit to satisfy "but does it..." questions.

- **Does not execute your code.** No `import`, no `subprocess`, no `eval` of detected snippets. The tool reads files as text. It does not run them.
- **Does not read environment variable VALUES.** It matches env-key NAMES against a provider catalogue. The value after `=` is never captured.
- **Does not read or write outside the scan root by design.** The file walker is bounded by the scan root; evidence paths that would resolve outside the tree render as `<outside-root>/{basename}` instead of leaking the user's filesystem layout.
- **Does not follow symlinks.** `read_text_safe` rejects any path with `S_ISLNK` set.
- **Does not transmit any data to APIsec, BlinkOps, Anthropic, OpenAI, or any third party.**
- **Does not require authentication or credentials** to run a scan. No OAuth, no API keys, no SSO, no AWS/GCP/Azure identity.
- **Does not write to `~`, `/tmp`, `/var`, or any system location.**
- **Does not modify the files it scans.** The tool is read-only with respect to the scanned tree.
- **Does not modify git state.** No `git commit`, no `git push`, no branch manipulation. The GitHub Action wrapper reads git history (for base-vs-head diff) but does not mutate it.
- **Does not classify or extract PII.** It flags non-literal data flowing into LLM calls (a structural pattern), nothing more.
- **Does not act as a secret scanner for secret VALUES.** For value-level secret scanning, use a dedicated tool such as gitleaks or GitGuardian.
- **Does not auto-update.** The version you install is the version that runs.

## Compliance posture

- **Data residency:** Every byte read and every byte written stays on the machine where you ran the tool. There is no cloud component to a CLI scan. The GitHub Action runs inside your GitHub-hosted (or self-hosted) runner; the only egress is the PR-comment API call to GitHub itself.
- **PII / sensitive data:** The tool does not classify PII, does not read secret values, and does not transmit findings off the machine. If your codebase contains PII (variable names, comments, fixture data), `ai-surface` will read those files like any text analyzer would, will pattern-match against its detection regexes, and will then either render text to stdout or write to the files you asked for. Nothing is transmitted.
- **License:** MIT. See [`LICENSE`](../LICENSE).
- **Source availability:** Full source is published under the same MIT license. Every detection, every file read, every output is auditable in the repo.

## How to verify this yourself

Pick whichever fits your environment:

```bash
# 1. Run in an isolated network namespace (Linux). Zero outbound packets.
sudo unshare -n ai-surface scan /path/to/repo

# 2. Run in a Docker container with no network.
docker run --rm --network=none -v "$PWD:/work" python:3.12 \
  bash -lc "pip install -q ai-surface && ai-surface scan /work"

# 3. strace network syscalls.
strace -f -e trace=network ai-surface scan /path/to/repo 2>&1 | grep -E "connect|send|sendto" || echo "no network syscalls"

# 4. tcpdump on the host interface while a scan runs.
sudo tcpdump -nn -i any not port 22 -c 50
```

If any of these produces unexpected network activity attributable to `ai-surface`, that is a confirmed contract violation and we treat it as a security incident. Please report it via the channel in [`SECURITY.md`](../SECURITY.md).

## Update history

| Date | Change |
|---|---|
| 2026-05-28 | Initial publication alongside v0.5.3. |
