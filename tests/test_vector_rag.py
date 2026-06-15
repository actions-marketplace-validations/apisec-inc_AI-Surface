"""Tests for the vector store / RAG detector."""
from __future__ import annotations

from ai_surface.detectors.vector_rag import VectorRagDetector
from ai_surface.types import CATEGORY_VECTOR_STORE


def _scan(tmp_path):
    return VectorRagDetector().detect(str(tmp_path))


def _by_surface(findings):
    return {f.surface: f for f in findings}


def test_pinecone_managed_python(tmp_path) -> None:
    (tmp_path / "rag.py").write_text(
        "import pinecone\nfrom langchain_openai import OpenAIEmbeddings\n"
        "pc = pinecone.Pinecone()\nemb = OpenAIEmbeddings()\n",
        encoding="utf-8")
    f = _by_surface(_scan(tmp_path))
    assert "Vector store: Pinecone" in f
    pc = f["Vector store: Pinecone"]
    assert pc.category == CATEGORY_VECTOR_STORE
    assert pc.evidence.metadata["store_type"] == "managed"
    assert pc.evidence.metadata["owasp"] == ["LLM08"]
    assert any("managed vector store" in r for r in pc.risk_indicators)
    assert any("embedded for retrieval" in r for r in pc.risk_indicators)


def test_pgvector_via_sql(tmp_path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION IF NOT EXISTS vector;\n"
        "CREATE INDEX ON items USING hnsw (embedding vector_cosine_ops);\n",
        encoding="utf-8")
    assert "Vector store: pgvector" in _by_surface(_scan(tmp_path))


def test_langchain_rag_retriever(tmp_path) -> None:
    (tmp_path / "chain.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "retriever = vectorstore.as_retriever()\n",
        encoding="utf-8")
    f = _by_surface(_scan(tmp_path))
    assert "RAG pipeline: LangChain" in f
    assert "Vector store: Chroma" in f
    assert any("retrieval-augmented generation" in r for r in f["RAG pipeline: LangChain"].risk_indicators)


def test_llamaindex_rag(tmp_path) -> None:
    (tmp_path / "idx.py").write_text(
        "from llama_index.core import VectorStoreIndex\n"
        "index = VectorStoreIndex.from_documents(docs)\n"
        "qe = index.as_query_engine()\n",
        encoding="utf-8")
    assert "RAG pipeline: LlamaIndex" in _by_surface(_scan(tmp_path))


def test_js_pinecone(tmp_path) -> None:
    (tmp_path / "store.ts").write_text(
        'import { Pinecone } from "@pinecone-database/pinecone";\n'
        "const pc = new Pinecone();\n",
        encoding="utf-8")
    f = _by_surface(_scan(tmp_path))
    assert "Vector store: Pinecone" in f
    assert "javascript/typescript" in f["Vector store: Pinecone"].evidence.metadata["languages"]


def test_external_loader_poisoning_indicator(tmp_path) -> None:
    (tmp_path / "ingest.py").write_text(
        "import chromadb\nfrom langchain_community.document_loaders import WebBaseLoader\n"
        "loader = WebBaseLoader('https://example.com')\n",
        encoding="utf-8")
    f = _by_surface(_scan(tmp_path))
    assert any("RAG poisoning" in r for r in f["Vector store: Chroma"].risk_indicators)


def test_no_false_positive(tmp_path) -> None:
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    assert _scan(tmp_path) == []


def test_elasticsearch_dense_vector(tmp_path) -> None:
    (tmp_path / "es.py").write_text(
        'mapping = {"embedding": {"type": "dense_vector", "dims": 1536}}\n', encoding="utf-8")
    assert "Vector store: Elasticsearch (vector)" in _by_surface(_scan(tmp_path))


def test_vespa_store(tmp_path) -> None:
    (tmp_path / "v.py").write_text("from vespa.application import Vespa\n", encoding="utf-8")
    assert "Vector store: Vespa" in _by_surface(_scan(tmp_path))


def test_plain_elasticsearch_not_flagged(tmp_path) -> None:
    # plain ES (no vector signal) must NOT be flagged as a vector store
    (tmp_path / "log.py").write_text("from elasticsearch import Elasticsearch\nes = Elasticsearch()\n", encoding="utf-8")
    assert _scan(tmp_path) == []
