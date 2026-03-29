# rag_builder - RAG知识库构建与检索模块
# 提供向量数据库构建、检索和缓存功能

from rag_builder.config import (
    BASE_DIR,
    WRITEUPS_DIR,
    CHROMA_DIR,
    EMBEDDING_MODEL,
    TOP_K_RESULTS,
    SIMILARITY_THRESHOLD
)

from rag_builder.cache import (
    RAGCache,
    get_cache,
    reset_cache,
    CACHE_TTL,
    CACHE_ENABLED
)

# 可选导入 - 需要chromadb和sentence_transformers
try:
    from rag_builder.retriever import (
        WriteupRetriever,
        get_retriever,
        retrieve_relevant_knowledge
    )
    from rag_builder.unified_vector_store import (
        UnifiedVectorStoreBuilder,
        UnifiedRetriever,
        get_unified_retriever
    )
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

__all__ = [
    # Config
    "BASE_DIR",
    "WRITEUPS_DIR",
    "CHROMA_DIR",
    "EMBEDDING_MODEL",
    "TOP_K_RESULTS",
    "SIMILARITY_THRESHOLD",
    # Cache
    "RAGCache",
    "get_cache",
    "reset_cache",
    "CACHE_TTL",
    "CACHE_ENABLED",
    # Retriever (may not be available)
    "WriteupRetriever",
    "get_retriever",
    "retrieve_relevant_knowledge",
    # Unified store (may not be available)
    "UnifiedVectorStoreBuilder",
    "UnifiedRetriever",
    "get_unified_retriever",
    # Status
    "RAG_AVAILABLE"
]