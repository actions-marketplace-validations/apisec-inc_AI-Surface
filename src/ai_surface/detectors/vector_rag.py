"""Vector store and RAG detector.

Scans Python and JS/TS (and .sql for pgvector) for vector databases and
retrieval-augmented-generation (RAG) pipelines: Pinecone, Weaviate, Chroma,
Qdrant, Milvus, FAISS, LanceDB, pgvector, and the LangChain / LlamaIndex
retrieval constructs.

RAG is the dominant enterprise AI pattern, so the retrieval layer is a
first-class AI surface. This detector inventories it and surfaces the
governance-relevant facts statically: a vector store is present, whether it is a
managed/cloud store (application data and embeddings leave your environment),
whether retrieved content reaches the model (the RAG data flow), and whether
ingestion pulls from external/untrusted sources (the RAG-poisoning surface).

Scope and boundary: discovery + configuration only. Like the other posture
detectors (LLM SDKs, gateways), findings are inventory with plain-English risk
indicators and carry no invented severity. We do NOT evaluate retrieval quality
or test for poisoning at runtime; that stays out of scope. Maps conceptually to
OWASP LLM08 (Vector and Embedding Weaknesses), LLM03 (Supply Chain), and the
EU AI Act Art. 10 / ISO A.7 data-governance requirements.
"""
from __future__ import annotations

import re
from re import Pattern

from ..types import CATEGORY_VECTOR_STORE, Evidence, Finding
from ..utils.walk import read_text_safe, relative_to_root, walk_files

# ---------------------------------------------------------------------------
# Signature table
# ---------------------------------------------------------------------------
#
# Each entry: (key, display, store_type, patterns). store_type is one of:
#   managed     - cloud/SaaS store; indexed data + embeddings leave the env
#   self-hosted - you run it (Chroma server, Qdrant, Milvus, Postgres+pgvector)
#   embedded    - in-process (FAISS, LanceDB)
#   framework   - a RAG retrieval pipeline abstraction (store may be indirect)
#
# Patterns cover Python imports/usage and JS/TS imports; pgvector also matches
# SQL (CREATE EXTENSION vector / ivfflat|hnsw index).

_SPECS: list[tuple[str, str, str, list[str]]] = [
    # Each store matches its native SDK AND its LangChain wrapper import
    # (`from langchain...vectorstores import <Class>` / `langchain_<store>`),
    # since RAG apps often reach the store through LangChain.
    ("pinecone", "Pinecone", "managed", [
        r"^\s*from\s+pinecone\b", r"^\s*import\s+pinecone\b",
        r"""['"]@pinecone-database/pinecone['"]""", r"\bPINECONE_API_KEY\b",
        r"from\s+langchain_pinecone\b", r"\.vectorstores\b[^\n]*\bPinecone\b",
    ]),
    ("weaviate", "Weaviate", "managed", [
        r"^\s*import\s+weaviate\b", r"^\s*from\s+weaviate\b",
        r"""['"]weaviate-(?:ts-)?client['"]""",
        r"from\s+langchain_weaviate\b", r"\.vectorstores\b[^\n]*\bWeaviate\b",
    ]),
    ("chroma", "Chroma", "self-hosted", [
        r"^\s*import\s+chromadb\b", r"^\s*from\s+chromadb\b", r"""['"]chromadb['"]""",
        r"from\s+langchain_chroma\b", r"\.vectorstores\b[^\n]*\bChroma\b",
    ]),
    ("qdrant", "Qdrant", "self-hosted", [
        r"^\s*from\s+qdrant_client\b", r"^\s*import\s+qdrant_client\b",
        r"""['"]@qdrant/js-client-rest['"]""", r"\bQdrantClient\s*\(",
        r"from\s+langchain_qdrant\b", r"\.vectorstores\b[^\n]*\bQdrant\b",
    ]),
    ("milvus", "Milvus", "self-hosted", [
        r"^\s*from\s+pymilvus\b", r"^\s*import\s+pymilvus\b",
        r"""['"]@zilliz/milvus2-sdk-node['"]""",
        r"from\s+langchain_milvus\b", r"\.vectorstores\b[^\n]*\bMilvus\b",
    ]),
    ("faiss", "FAISS", "embedded", [
        r"^\s*import\s+faiss\b", r"^\s*from\s+faiss\b", r"""['"]faiss-node['"]""",
        r"\.vectorstores\b[^\n]*\bFAISS\b",
    ]),
    ("lancedb", "LanceDB", "embedded", [
        r"^\s*import\s+lancedb\b", r"^\s*from\s+lancedb\b",
        r"""['"]@lancedb/lancedb['"]""", r"""['"]vectordb['"]""",
        r"\.vectorstores\b[^\n]*\bLanceDB\b",
    ]),
    ("pgvector", "pgvector", "self-hosted", [
        r"^\s*from\s+pgvector\b", r"^\s*import\s+pgvector\b", r"""['"]pgvector['"]""",
        r"CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?['\"]?vector",
        r"USING\s+(?:ivfflat|hnsw)\b",
        r"from\s+langchain_postgres\b", r"\.vectorstores\b[^\n]*\bPGVector\b",
    ]),
    ("langchain_rag", "LangChain", "framework", [
        r"from\s+langchain(?:_community|_core|_[a-z]+)?\.vectorstores\b",
        r"\.as_retriever\s*\(", r"\bRetrievalQA\b", r"\bVectorStoreRetriever\b",
        r"\.asRetriever\s*\(",
    ]),
    ("llamaindex_rag", "LlamaIndex", "framework", [
        r"\bVectorStoreIndex\b", r"\.as_query_engine\s*\(",
        r"\bVectorIndexRetriever\b",
    ]),
]

_COMPILED: list[tuple[str, str, str, list[Pattern[str]]]] = [
    (key, display, store_type, [re.compile(p, re.MULTILINE | re.IGNORECASE) for p in pats])
    for key, display, store_type, pats in _SPECS
]

# Repo-level signals that sharpen the RAG risk indicators.
_EMBEDDINGS_RE = re.compile(
    r"\bOpenAIEmbeddings\b|\bHuggingFaceEmbeddings\b|\bCohereEmbeddings\b|"
    r"\bSentenceTransformer\b|\bembed_query\b|\bembed_documents\b|"
    r"""['"]text-embedding-[\w.-]+['"]""",
    re.IGNORECASE,
)
# Ingestion from external/untrusted content = the RAG-poisoning surface.
_EXTERNAL_LOADER_RE = re.compile(
    r"\bWebBaseLoader\b|\bRecursiveUrlLoader\b|\bSitemapLoader\b|"
    r"\bUnstructuredURLLoader\b|\bFireCrawlLoader\b|\bAsyncHtmlLoader\b",
)

_EXTENSIONS = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".sql")


class VectorRagDetector:
    """Detects vector stores and RAG pipelines in Python and JS/TS source."""

    name = "vector_rag"
    category = CATEGORY_VECTOR_STORE

    def detect(self, root_path: str) -> list[Finding]:
        files_by_key: dict[str, list[str]] = {}
        snippet_by_key: dict[str, str] = {}
        languages_by_key: dict[str, set[str]] = {}
        spec_by_key = {key: (display, store_type) for key, display, store_type, _ in _COMPILED}

        repo_has_embeddings = False
        repo_has_external_loader = False
        repo_has_rag = False  # any framework retriever construct present

        for file_path in walk_files(root_path, extensions=list(_EXTENSIONS)):
            text = read_text_safe(file_path)
            if not text:
                continue
            rel = relative_to_root(file_path, root_path)
            lang = "python" if file_path.suffix.lower() == ".py" else (
                "sql" if file_path.suffix.lower() == ".sql" else "javascript/typescript")

            if _EMBEDDINGS_RE.search(text):
                repo_has_embeddings = True
            if _EXTERNAL_LOADER_RE.search(text):
                repo_has_external_loader = True

            for key, _display, store_type, pats in _COMPILED:
                line = _first_match_line(text, pats)
                if line is None:
                    continue
                files_by_key.setdefault(key, []).append(rel)
                snippet_by_key.setdefault(key, line)
                languages_by_key.setdefault(key, set()).add(lang)
                if store_type == "framework":
                    repo_has_rag = True

        findings: list[Finding] = []
        for key, _display, store_type, _ in _COMPILED:
            if key not in files_by_key:
                continue
            display, store_type = spec_by_key[key]
            is_framework = store_type == "framework"
            surface = f"RAG pipeline: {display}" if is_framework else f"Vector store: {display}"
            findings.append(
                Finding(
                    surface=surface,
                    category=CATEGORY_VECTOR_STORE,
                    evidence=Evidence(
                        files=sorted(set(files_by_key[key])),
                        snippet=snippet_by_key.get(key, "")[:200],
                        metadata={
                            "store_type": store_type,
                            "languages": sorted(languages_by_key.get(key, set())),
                            "owasp": ["LLM08"],
                        },
                    ),
                    risk_indicators=_risk_indicators(
                        store_type, is_framework, repo_has_rag,
                        repo_has_embeddings, repo_has_external_loader,
                    ),
                )
            )
        return findings


def _first_match_line(text: str, pats: list[Pattern[str]]) -> str | None:
    """Return the trimmed line of the first matching pattern, or None."""
    for pat in pats:
        m = pat.search(text)
        if not m:
            continue
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        return text[start: end if end != -1 else len(text)].strip()[:200]
    return None


def _risk_indicators(
    store_type: str, is_framework: bool, repo_has_rag: bool,
    has_embeddings: bool, has_external_loader: bool,
) -> list[str]:
    """Plain-English, severity-free indicators for a vector/RAG surface."""
    out: list[str] = []
    if store_type == "managed":
        out.append("managed vector store (indexed data and embeddings leave your environment)")
    if is_framework or repo_has_rag:
        out.append("retrieved content reaches the model (retrieval-augmented generation)")
    if has_embeddings:
        out.append("application data embedded for retrieval")
    if has_external_loader:
        out.append("ingests external content (RAG poisoning surface)")
    return out


__all__ = ["VectorRagDetector"]
