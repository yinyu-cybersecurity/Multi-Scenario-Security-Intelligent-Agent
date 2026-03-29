# rag_builder/retriever.py - 检索接口
# 作用：供头脑风暴兵调用，返回相似WP和相关知识
# 更新：支持统一检索器（Writeups + Nuclei + Payloads + Security Resources）
# 更新：集成RAG缓存机制，减少重复向量查询

from typing import List, Dict, Tuple, Optional

# Optional dependencies - RAG functionality requires these
try:
    import chromadb
    from sentence_transformers import SentenceTransformer
    RAG_AVAILABLE = True
except ImportError:
    chromadb = None
    SentenceTransformer = None
    RAG_AVAILABLE = False

from rag_builder.config import CHROMA_DIR, EMBEDDING_MODEL, TOP_K_RESULTS, SIMILARITY_THRESHOLD
from rag_builder.cache import get_cache, RAGCache

# 尝试导入统一检索器
try:
    from rag_builder.unified_vector_store import get_unified_retriever
    UNIFIED_RETRIEVER_AVAILABLE = True
except ImportError:
    get_unified_retriever = None
    UNIFIED_RETRIEVER_AVAILABLE = False


class WriteupRetriever:
    """Writeup检索器 - 支持统一检索"""

    def __init__(self, use_unified: bool = True):
        """初始化检索器"""
        if not RAG_AVAILABLE:
            raise ImportError("RAG functionality requires chromadb and sentence_transformers")

        print("[RAG] Initializing retriever...")

        # 如果可用，优先使用统一检索器
        if use_unified and UNIFIED_RETRIEVER_AVAILABLE:
            print("[RAG] Using unified retriever (Writeups + Nuclei + Payloads)")
            self._unified = get_unified_retriever()
            self._use_unified = True
        else:
            print("[RAG] Using legacy retriever (Writeups only)")
            self._use_unified = False
            self._init_legacy_components()

        self.count = self._get_total_count()
        print(f"[RAG] Retriever ready, knowledge base contains {self.count} records")

    def _init_legacy_components(self):
        """初始化旧版组件"""
        self._client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self._collection = self._client.get_or_create_collection("ctf_writeups")
        self._model = SentenceTransformer(EMBEDDING_MODEL)
        self.count = self._collection.count()

    def _get_total_count(self) -> int:
        """获取总记录数"""
        if self._use_unified:
            # 统一检索器已经统计过了
            total = 0
            if hasattr(self._unified, 'writeups_collection') and self._unified.writeups_collection:
                total += self._unified.writeups_collection.count() if self._unified.writeups_collection else 0
            if hasattr(self._unified, 'nuclei_collection') and self._unified.nuclei_collection:
                total += self._unified.nuclei_collection.count() if self._unified.nuclei_collection else 0
            if hasattr(self._unified, 'payloads_collection') and self._unified.payloads_collection:
                total += self._unified.payloads_collection.count() if self._unified.payloads_collection else 0
            if hasattr(self._unified, 'security_resources_collection') and self._unified.security_resources_collection:
                total += self._unified.security_resources_collection.count() if self._unified.security_resources_collection else 0
            return total
        return self._collection.count() if hasattr(self, '_collection') else 0

    def _ensure_client_alive(self):
        """确保客户端可用"""
        if self._use_unified:
            return  # 统一检索器自动处理
        try:
            _ = self._collection.count()
        except Exception as e:
            if "closed" in str(e).lower() or "client" in str(e).lower():
                print("[RAG] Client was closed, re-initializing...")
                self._init_legacy_components()
            else:
                raise

    def search_by_text(self, query: str, top_k: int = TOP_K_RESULTS,
                       sources: Tuple[str, ...] = None, use_cache: bool = True) -> List[Dict]:
        """
        用文本检索相似内容

        Args:
            query: 查询文本
            top_k: 返回结果数量
            sources: 数据源元组，如 ("writeups", "nuclei")
            use_cache: 是否使用缓存（默认True）

        Returns:
            相似内容列表
        """
        # 确定数据源
        if sources is None:
            sources = ("writeups", "nuclei", "payloads", "security_resources")

        # 尝试从缓存获取
        if use_cache:
            cache = get_cache()
            cached_results = cache.get(query, sources, top_k)
            if cached_results is not None:
                return cached_results

        # 执行实际查询
        if self._use_unified:
            # 使用统一检索器（包含所有数据源）
            results = self._unified.search(query, top_k=top_k, sources=list(sources))
            # 合并所有结果
            all_results = []
            for source in sources:
                if source in results and results[source]:
                    for item in results[source]:
                        item["source"] = source
                        all_results.append(item)
            # 按相似度排序并过滤
            all_results.sort(key=lambda x: x.get("similarity", 0), reverse=True)
            filtered = [r for r in all_results if r.get("similarity", 0) >= SIMILARITY_THRESHOLD]
            result = filtered[:top_k]
        else:
            result = self._legacy_search_by_text(query, top_k)

        # 缓存结果
        if use_cache and result:
            cache.set(query, result, sources, top_k)

        return result

    def _legacy_search_by_text(self, query: str, top_k: int) -> List[Dict]:
        """旧版文本检索"""
        self._ensure_client_alive()
        query_embedding = self._model.encode(query).tolist()

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["documents", "metadatas", "distances"]
        )

        formatted = []
        if results['ids'][0]:
            for i in range(len(results['ids'][0])):
                distance = results['distances'][0][i]
                similarity = 1 - distance

                if similarity >= SIMILARITY_THRESHOLD:
                    formatted.append({
                        "id": results['ids'][0][i],
                        "content": results['documents'][0][i],
                        "metadata": results['metadatas'][0][i],
                        "similarity": round(similarity, 3)
                    })

        return formatted

    def search_by_features(self, features: Dict, top_k: int = TOP_K_RESULTS) -> List[Dict]:
        """
        根据页面特征检索（供头脑风暴兵直接调用）

        Args:
            features: 侦察兵提取的页面特征
            top_k: 返回数量
        """
        # 构建更精准的查询文本
        query_parts = []

        # 1. 技术栈
        tech_stack = features.get("tech_stack", [])
        if tech_stack:
            query_parts.append(f"technology: {', '.join(tech_stack)}")

        # 2. 输入向量 - 重点标注漏洞入口
        input_vectors = features.get("input_vectors", [])
        if input_vectors:
            # 提取输入类型（如 GET, POST）
            input_types = set()
            for iv in input_vectors:
                if ":" in str(iv):
                    input_types.add(str(iv).split(":")[0])
            if input_types:
                query_parts.append(f"input type: {', '.join(input_types)}")
            query_parts.append(f"parameters: {', '.join(str(v) for v in input_vectors)}")

        # 3. 敏感路径
        paths = features.get("sensitive_paths", [])
        if paths:
            query_parts.append(f"sensitive paths: {', '.join(paths[:5])}")

        # 4. 标签
        tags = features.get("tags", [])
        if tags:
            query_parts.append(f"vulnerability type: {', '.join(tags)}")

        query = " | ".join(query_parts) if query_parts else "CTF Web vulnerability"

        print(f"   [RAG] Query: {query[:100]}...")
        return self.search_by_text(query, top_k)

    def search_by_tags(self, tags: List[str], top_k: int = TOP_K_RESULTS) -> List[Dict]:
        """根据tags检索"""
        self._ensure_client_alive()

        # 通过metadata过滤
        where_clause = {"$or": [{"tags": {"$contains": tag}} for tag in tags]}

        results = self._collection.query(
            query_texts=[" "],  # 空查询，只过滤
            n_results=top_k,
            where=where_clause
        )

        formatted = []
        if results['ids'][0]:
            for i in range(len(results['ids'][0])):
                formatted.append({
                    "id": results['ids'][0][i],
                    "content": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i]
                })

        return formatted

    def search_by_vuln_type(self, vuln_type: str, top_k: int = 10) -> List[Dict]:
        """按漏洞类型检索"""
        query = f"vulnerability type: {vuln_type}"
        return self.search_by_text(query, top_k)

    def search_by_cve(self, cve_id: str) -> List[Dict]:
        """按CVE编号检索"""
        query = f"CVE ID: {cve_id}"
        return self.search_by_text(query, top_k=3)


# 全局单例（避免重复加载模型）
_retriever = None


def get_retriever() -> WriteupRetriever:
    """获取检索器实例（单例模式）"""
    global _retriever
    if _retriever is None:
        _retriever = WriteupRetriever()
    return _retriever


def retrieve_relevant_knowledge(query: str, sources: list = None, top_k: int = 5,
                                use_cache: bool = True) -> List[Dict]:
    """
    Unified knowledge retrieval function for RAG.

    This is the main entry point for retrieving relevant knowledge from the vector database.
    Used by multiple nodes across the codebase (ai_security, cloud_security, misc, etc.).

    Args:
        query: The search query string
        sources: List of sources to search from.
                 Valid options: ["writeups", "nuclei", "payloads", "security_resources"]
                 Default: ["writeups", "security_resources"]
        top_k: Number of results to return per source (default: 5)
        use_cache: Whether to use cache (default: True)

    Returns:
        List of dicts with keys: "content", "similarity", "metadata", "source"
        Returns empty list on failure (graceful degradation)
    """
    if sources is None:
        sources = ["writeups", "security_resources"]

    # Convert sources to tuple for cache key
    sources_tuple = tuple(sources)

    # Try to get from cache first
    if use_cache:
        cache = get_cache()
        cached_results = cache.get(query, sources_tuple, top_k)
        if cached_results is not None:
            return cached_results

    results = []

    try:
        # Try using the unified retriever first (supports all sources)
        if UNIFIED_RETRIEVER_AVAILABLE:
            retriever = get_unified_retriever()
            raw_results = retriever.search(query, top_k=top_k, sources=sources)

            # Flatten results from all sources into a single list
            for source in sources:
                if source in raw_results and raw_results[source]:
                    for item in raw_results[source]:
                        results.append({
                            "content": item.get("content", ""),
                            "similarity": item.get("similarity", 0),
                            "metadata": item.get("metadata", {}),
                            "source": source
                        })

            # Sort by similarity (highest first)
            results.sort(key=lambda x: x.get("similarity", 0), reverse=True)

            # Return top_k * len(sources) results max
            max_results = top_k * len(sources)
            results = results[:max_results]

        else:
            # Fallback to legacy retriever (writeups only)
            retriever = get_retriever()
            legacy_results = retriever.search_by_text(query, top_k=top_k, use_cache=False)

            for item in legacy_results:
                results.append({
                    "content": item.get("content", ""),
                    "similarity": item.get("similarity", 0),
                    "metadata": item.get("metadata", {}),
                    "source": "writeups"
                })

        # Cache the results
        if use_cache and results:
            cache.set(query, results, sources_tuple, top_k)

        return results

    except ImportError as e:
        # RAG dependencies not available
        print(f"[RAG] Warning: RAG dependencies not available: {e}")
        return []
    except Exception as e:
        # Any other error - log and return empty list (graceful degradation)
        print(f"[RAG] Error retrieving knowledge: {e}")
        return []


# 简单测试
if __name__ == "__main__":
    retriever = get_retriever()

    # 测试搜索
    results = retriever.search_by_text("SQL injection")
    print(f"\nFound {len(results)} results")
    for r in results[:3]:
        print(f"  - [{r.get('source', 'unknown')}] {r['metadata']['filename']} (similarity: {r['similarity']})")