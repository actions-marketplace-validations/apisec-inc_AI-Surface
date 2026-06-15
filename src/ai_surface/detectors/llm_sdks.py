"""LLM SDK call site detector.

Scans Python and JS/TS source for imports/usages of common LLM provider SDKs
(Anthropic, OpenAI, Bedrock, Azure OpenAI, Google Generative AI, Vertex AI,
Together, Mistral, Cohere, Replicate, Groq, LiteLLM).

Each detected SDK aggregates into ONE Finding with a list of files where it
appears. Best-effort model name extraction and a light data-flow heuristic
populate evidence.metadata and risk_indicators respectively.
"""
from __future__ import annotations

import re
from re import Pattern

from ..types import CATEGORY_LLM_SDK, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

# ---------------------------------------------------------------------------
# SDK signature table
# ---------------------------------------------------------------------------
#
# Each entry: surface name -> list of regex patterns that, if any match, mean
# this SDK is present in the file. Patterns are compiled once at module load.
#
# Note: Azure OpenAI is treated as its own surface even though it shares the
# `openai` package, because the deployment model and key surface are distinct.

_SDK_PATTERNS: dict[str, list[str]] = {
    "Anthropic SDK": [
        # Python
        r"^\s*from\s+anthropic(\.|\s+import\b)",
        r"^\s*import\s+anthropic\b",
        # JS/TS
        r"""['"]@anthropic-ai/sdk['"]""",
    ],
    "OpenAI SDK": [
        # Python: import openai or from openai import X (but NOT AzureOpenAI; handled below)
        r"^\s*from\s+openai\s+import\s+(?!AzureOpenAI\b)",
        r"^\s*from\s+openai(\.|\s*$)",
        r"^\s*import\s+openai\b",
        # JS/TS: from "openai" (not @azure/openai)
        r"""from\s+['"]openai['"]""",
        r"""require\(\s*['"]openai['"]\s*\)""",
    ],
    "Azure OpenAI": [
        # Python
        r"^\s*from\s+openai\s+import\s+[^#\n]*\bAzureOpenAI\b",
        r"\bAzureOpenAI\s*\(",
        # JS/TS
        r"""\bAzureOpenAI\b""",
        # Env-pattern hint
        r"\bAZURE_OPENAI_[A-Z_]+\b",
    ],
    "AWS Bedrock": [
        # Python: boto3.client("bedrock") or "bedrock-runtime"
        r"""boto3\.client\(\s*['"]bedrock(-runtime)?['"]""",
        r"""boto3\.client\(\s*service_name\s*=\s*['"]bedrock(-runtime)?['"]""",
        # Python: AWS Strands SDK's Bedrock wrapper
        r"^\s*from\s+strands\.models\s+import\s+[^#\n]*\bBedrockModel\b",
        r"\bBedrockModel\s*\(",
        # JS/TS
        r"""['"]@aws-sdk/client-bedrock(-runtime)?['"]""",
    ],
    "Google Generative AI": [
        r"^\s*from\s+google\.generativeai\b",
        r"^\s*import\s+google\.generativeai\b",
        r"""['"]@google/generative-ai['"]""",
    ],
    "Google Vertex AI": [
        r"^\s*from\s+google\.cloud\s+import\s+[^#\n]*\baiplatform\b",
        r"^\s*from\s+vertexai\b",
        r"^\s*import\s+vertexai\b",
        r"""['"]@google-cloud/aiplatform['"]""",
    ],
    "Together": [
        r"^\s*from\s+together\b",
        r"^\s*import\s+together\b",
        r"""['"]together-ai['"]""",
    ],
    "Mistral": [
        r"^\s*from\s+mistralai\b",
        r"^\s*import\s+mistralai\b",
        r"""['"]@mistralai/mistralai['"]""",
    ],
    "Cohere": [
        r"^\s*from\s+cohere\b",
        r"^\s*import\s+cohere\b",
        r"""['"]cohere-ai['"]""",
    ],
    "Replicate": [
        r"^\s*from\s+replicate\b",
        r"^\s*import\s+replicate\b",
        r"""['"]replicate['"]""",
    ],
    "Groq": [
        r"^\s*from\s+groq\b",
        r"^\s*import\s+groq\b",
        r"""['"]groq-sdk['"]""",
    ],
    "LiteLLM": [
        r"^\s*from\s+litellm\b",
        r"^\s*import\s+litellm\b",
    ],
    "Vercel AI SDK": [
        # The `ai` package (Vercel AI SDK) and its provider adapters. Common in
        # TS apps that never import a provider SDK directly.
        r"""from\s+['"]ai['"]""",
        r"""require\(\s*['"]ai['"]\s*\)""",
        r"""['"]@ai-sdk/""",
    ],
}

# Compile once.
_COMPILED: dict[str, list[Pattern[str]]] = {
    surface: [re.compile(p, re.MULTILINE) for p in patterns]
    for surface, patterns in _SDK_PATTERNS.items()
}


# Order matters here: Azure OpenAI checked before plain OpenAI so we don't
# double-count an `AzureOpenAI` file as plain OpenAI as well.
_DETECTION_ORDER = [
    "Azure OpenAI",
    "Anthropic SDK",
    "OpenAI SDK",
    "AWS Bedrock",
    "Google Generative AI",
    "Google Vertex AI",
    "Together",
    "Mistral",
    "Cohere",
    "Replicate",
    "Groq",
    "LiteLLM",
    "Vercel AI SDK",
]


# ---------------------------------------------------------------------------
# Model name extraction
# ---------------------------------------------------------------------------
#
# Match common model string literals like "claude-sonnet-4-6", "gpt-4-turbo",
# "text-embedding-3-large", "meta.llama-3-70b", "mistral-large-latest",
# "command-r-plus", "gemini-1.5-pro".
#
# Kept intentionally permissive: this is signal for a human, not a contract.

# Bedrock model IDs (e.g. "anthropic.claude-3-5-sonnet-20240620-v1:0") have a
# `:N` version suffix, so the Bedrock-prefixed alternatives include `:` in
# their character class. Provider-prefixed regexes are placed before bare
# `claude-` / `command-` / `llama-` so they win on the alternation.
_MODEL_LITERAL = re.compile(
    r"""['"]
    (
        (?:[a-z]{2,4}\.)?anthropic\.claude-[a-z0-9.:_-]+
      | (?:[a-z]{2,4}\.)?amazon\.titan-[a-z0-9.:_-]+
      | (?:[a-z]{2,4}\.)?amazon\.nova-[a-z0-9.:_-]+
      | (?:[a-z]{2,4}\.)?meta\.llama[a-z0-9.:_-]*
      | (?:[a-z]{2,4}\.)?mistral\.[a-z0-9.:_-]+
      | (?:[a-z]{2,4}\.)?cohere\.command-[a-z0-9.:_-]+
      | claude-[a-z0-9._-]+
      | gpt-[a-z0-9._-]+
      | o[1-9](?:-[a-z0-9._-]+)?
      | text-embedding-[a-z0-9._-]+
      | llama-?[0-9][a-z0-9._-]*
      | mistral-[a-z0-9._-]+
      | mixtral-[a-z0-9._-]+
      | command-[a-z0-9._-]+
      | gemini-[a-z0-9._-]+
    )
    ['"]""",
    re.VERBOSE | re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data-flow heuristic
# ---------------------------------------------------------------------------
#
# Look for `messages=` blocks where a "content" value is a non-string-literal,
# or `prompt=<bareword>` (not a quoted string). Both are noisy signals that
# something dynamic is flowing into an LLM call.

# content: <non-string> within a messages dict.
# Matches both Python-style (`"content": var`) and TypeScript-style
# (`content: var`) object literals. The non-capturing alternation handles
# the unquoted JS/TS form via word boundary; lookbehind keeps us from
# matching inside identifiers like `display_content:`.
_CONTENT_NONLITERAL = re.compile(
    r"""(?:['"]content['"]|(?<![\w])content)\s*:\s*(?!['"`])([A-Za-z_][\w\.\[\]]*)""",
)

# prompt= or input= with a bareword RHS (Python kwarg style)
_PROMPT_NONLITERAL = re.compile(
    r"""\b(?:prompt|input|user_input|query)\s*=\s*(?!['"`f]|r['"]|b['"])([A-Za-z_][\w\.\[\]]*)""",
)

# Identifiers that look "non-literal" syntactically but are actually
# language constants. None/True/False as a kwarg value isn't a data flow.
_NONFLOW_IDENTIFIERS = frozenset({
    "None", "True", "False", "Ellipsis", "NotImplemented",  # Python
    "null", "true", "false", "undefined", "NaN",            # JS/TS
})


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class LlmSdkDetector:
    """Detects LLM provider SDK call sites in Python and JS/TS source."""

    name = "llm_sdks"
    category = CATEGORY_LLM_SDK

    EXTENSIONS: tuple[str, ...] = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs")

    def detect(self, root_path: str) -> list[Finding]:
        """Walk root_path and emit one Finding per detected SDK."""
        # Per-SDK accumulators.
        files_by_sdk: dict[str, list[str]] = {}
        snippet_by_sdk: dict[str, str] = {}
        models_by_sdk: dict[str, list[str]] = {}
        call_count_by_sdk: dict[str, int] = {}
        flow_risk_by_sdk: dict[str, bool] = {}

        for file_path in walk_files(root_path, extensions=list(self.EXTENSIONS)):
            text = read_text_safe(file_path)
            if not text:
                continue

            matched_sdks_in_file = self._detect_sdks_in_text(text)
            if not matched_sdks_in_file:
                continue

            rel = relative_to_root(file_path, root_path)
            file_models = _extract_models(text)
            file_has_nonliteral_flow = _has_nonliteral_flow(text)

            # Per-SDK model attribution. When only one SDK is in the file, all
            # models go to it. When multiple SDKs share a file, partition models
            # by their naming family so we don't mis-attribute (e.g., showing
            # gpt-4 under Anthropic SDK or claude-sonnet under OpenAI SDK).
            sdks_in_file = list(matched_sdks_in_file.keys())
            models_per_sdk = _partition_models_by_sdk(file_models, sdks_in_file)

            for sdk, snippet in matched_sdks_in_file.items():
                files_by_sdk.setdefault(sdk, []).append(rel)
                # First snippet wins; keeps detection deterministic (walk order).
                snippet_by_sdk.setdefault(sdk, snippet)
                if models_per_sdk.get(sdk):
                    bucket = models_by_sdk.setdefault(sdk, [])
                    for m in models_per_sdk[sdk]:
                        if m not in bucket:
                            bucket.append(m)
                # Approximate call-site count: one per file the SDK appears in.
                # A more exact count (per `client.messages.create(` etc.) could
                # come in v0.6 with light AST parsing.
                call_count_by_sdk[sdk] = call_count_by_sdk.get(sdk, 0) + 1
                if file_has_nonliteral_flow:
                    flow_risk_by_sdk[sdk] = True

        findings: list[Finding] = []
        for sdk in _DETECTION_ORDER:
            if sdk not in files_by_sdk:
                continue
            files = sorted(set(files_by_sdk[sdk]))
            evidence = Evidence(
                files=files,
                snippet=snippet_by_sdk.get(sdk, "")[:200],
                metadata={
                    "models_used": models_by_sdk.get(sdk, []),
                    "call_site_count": call_count_by_sdk.get(sdk, 0),
                },
            )
            risk_indicators: list[str] = []
            if flow_risk_by_sdk.get(sdk):
                risk_indicators.append("non-literal data flows into LLM call")
            findings.append(
                Finding(
                    surface=sdk,
                    category=CATEGORY_LLM_SDK,
                    evidence=evidence,
                    permissions=[],
                    risk_indicators=risk_indicators,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_sdks_in_text(text: str) -> dict[str, str]:
        """Return a mapping of SDK name -> representative line for matches in text.

        Uses _DETECTION_ORDER so Azure OpenAI is matched before plain OpenAI.
        A single file may match multiple SDKs (e.g., a file using both
        `anthropic` and `openai`).
        """
        out: dict[str, str] = {}
        for sdk in _DETECTION_ORDER:
            for pat in _COMPILED[sdk]:
                m = pat.search(text)
                if not m:
                    continue
                # Pull the matching line for snippet, trimmed.
                line_start = text.rfind("\n", 0, m.start()) + 1
                line_end = text.find("\n", m.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end].strip()
                out[sdk] = line
                # If this is OpenAI SDK and Azure already matched in same file,
                # keep both — Azure imports from openai too, but a file that
                # imports both AzureOpenAI and OpenAI is legitimately using both.
                break
        # If both Azure OpenAI and OpenAI SDK match because of the shared
        # `openai` import line, drop OpenAI SDK only when the *only* OpenAI
        # signal is the AzureOpenAI import line itself. We approximate this
        # by checking whether OpenAI SDK matched purely via the
        # `from openai import ... AzureOpenAI ...` form with no other import.
        if (
            "Azure OpenAI" in out
            and "OpenAI SDK" in out
            and _openai_only_via_azure_import(text)
        ):
            out.pop("OpenAI SDK", None)
        return out


def _openai_only_via_azure_import(text: str) -> bool:
    """True if every `openai` import in the file also imports AzureOpenAI.

    Used to suppress double-counting: a file that does only
    `from openai import AzureOpenAI` should produce Azure OpenAI, not also
    OpenAI SDK.
    """
    openai_imports = re.findall(
        r"^\s*(?:from\s+openai\s+import\s+[^\n]+|import\s+openai\b[^\n]*)",
        text,
        re.MULTILINE,
    )
    if not openai_imports:
        return False
    return all("AzureOpenAI" in line for line in openai_imports)


def _extract_models(text: str) -> list[str]:
    """Pull out plausible model names mentioned as string literals."""
    seen: list[str] = []
    for m in _MODEL_LITERAL.finditer(text):
        name = m.group(1)
        if name not in seen:
            seen.append(name)
    return seen


# Model name family heuristics. When a file matches multiple SDKs, each model
# string is attributed to the SDK that best fits its naming family. This avoids
# misattributing `gpt-4-turbo` to Anthropic SDK or `claude-sonnet-...` to OpenAI
# SDK simply because both happen to be imported in the same file.
_MODEL_AFFINITY: list[tuple[str, re.Pattern[str]]] = [
    # Bedrock-prefixed models (with optional cross-region inference profile)
    (
        "AWS Bedrock",
        re.compile(
            r"^(?:[a-z]{2,4}\.)?(?:anthropic\.|amazon\.|meta\.|mistral\.|cohere\.)",
            re.IGNORECASE,
        ),
    ),
    ("Anthropic SDK", re.compile(r"^claude-", re.IGNORECASE)),
    ("OpenAI SDK", re.compile(r"^(?:gpt-|o[1-9]|text-embedding-)", re.IGNORECASE)),
    ("Azure OpenAI", re.compile(r"^(?:gpt-|o[1-9]|text-embedding-)", re.IGNORECASE)),
    ("Google Generative AI", re.compile(r"^gemini-", re.IGNORECASE)),
    ("Google Vertex AI", re.compile(r"^gemini-", re.IGNORECASE)),
    ("Mistral", re.compile(r"^(?:mistral-|mixtral-)", re.IGNORECASE)),
    ("Cohere", re.compile(r"^command-", re.IGNORECASE)),
    ("Groq", re.compile(r"^(?:llama-|mixtral-)", re.IGNORECASE)),
]


def _partition_models_by_sdk(models: list[str], sdks_in_file: list[str]) -> dict[str, list[str]]:
    """Attribute each model name to the SDK that best matches its naming family.

    Single-SDK files: all models go to the lone SDK (preserves original behavior).
    Multi-SDK files: per-model affinity rules. Models that don't match any
    affinity rule fall back to the first SDK in the file (deterministic).
    """
    if len(sdks_in_file) == 1:
        return {sdks_in_file[0]: models}

    out: dict[str, list[str]] = {sdk: [] for sdk in sdks_in_file}
    for model in models:
        attributed = False
        for sdk_name, pattern in _MODEL_AFFINITY:
            if sdk_name in sdks_in_file and pattern.match(model):
                out[sdk_name].append(model)
                attributed = True
                break
        if not attributed:
            # No clear affinity. Fall back to the first SDK in the file so the
            # model still shows up somewhere rather than being dropped.
            out[sdks_in_file[0]].append(model)
    return out


def _has_nonliteral_flow(text: str) -> bool:
    """Return True if a non-literal value appears to flow into an LLM call.

    Heuristic-only: scans for `"content": <bareword>` or
    `prompt=<bareword>` (no quote, no f-string). False positives possible.
    """
    if any(
        m.group(1) not in _NONFLOW_IDENTIFIERS
        for m in _CONTENT_NONLITERAL.finditer(text)
    ):
        return True
    return any(
        m.group(1) not in _NONFLOW_IDENTIFIERS
        for m in _PROMPT_NONLITERAL.finditer(text)
    )
