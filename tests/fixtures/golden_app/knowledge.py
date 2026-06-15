"""RAG over the product knowledge base (pgvector + LangChain)."""
from langchain_postgres import PGVector
from langchain_openai import OpenAIEmbeddings
from langchain_community.document_loaders import WebBaseLoader

embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
loader = WebBaseLoader("https://help.example.com/articles")  # external ingestion
store = PGVector(embeddings=embeddings, collection_name="kb")
retriever = store.as_retriever()
