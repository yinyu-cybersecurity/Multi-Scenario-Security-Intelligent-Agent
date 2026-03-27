# rag_builder/retriever.py - 检索接口
# 作用：供头脑风暴兵调用，返回相似WP

import os
from pathlib import Path
from typing import List, Dict, Optional

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


class WriteupRetriever:
    """Writeup检索器"""

    def __init__(self):
        """初始化检索器（只需一次）"""
        if not RAG_AVAILABLE:
            raise ImportError("RAG functionality requires chromadb and sentence_transformers. Install with: pip install chromadb sentence-transformers")

        print("[RAG] Initializing retriever...")

        # 初始化状态
        self._client = None
        self._collection = None
        self._model = None

        # 执行初始化
        self._init_components()

    def _init_components(self):
        """初始化或重新初始化组件"""
        # 1. 连接ChromaDB
        self._client = chromadb.PersistentClient(path=str(CHROMA_DIR))
        self._collection = self._client.get_or_create_collection("ctf_writeups")

        # 2. 加载embedding模型
        self._model = SentenceTransformer(EMBEDDING_MODEL)

        # 3. 统计信息
        self.count = self._collection.count()
        print(f"[RAG] Retriever ready, knowledge base contains {self.count} records")

    def _ensure_client_alive(self):
        """确保客户端可用，如果已关闭则重新初始化"""
        try:
            # 尝试一个简单操作来检测客户端是否存活
            _ = self._collection.count()
        except Exception as e:
            if "closed" in str(e).lower() or "client" in str(e).lower():
                print("[RAG] Client was closed, re-initializing...")
                self._init_components()
            else:
                raise

    def search_by_text(self, query: str, top_k: int = TOP_K_RESULTS) -> List[Dict]:
        """
        用文本检索相似Writeup

        Args:
            query: 查询文本（如 "SQL注入 bypass WAF"）
            top_k: 返回数量

        Returns:
            [
                {
                    "content": "WP内容...",
                    "metadata": {"filename": "...", "tags": [...]},
                    "similarity": 0.85
                }
            ]
        """
        # 确保客户端可用
        self._ensure_client_alive()

        # 1. 计算查询向量
        query_embedding = self._model.encode(query).tolist()

        # 2. 检索
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["documents", "metadatas", "distances"]
        )

        # 3. 格式化返回
        formatted = []
        if results['ids'][0]:
            for i in range(len(results['ids'][0])):
                # 计算相似度（距离转相似度）
                distance = results['distances'][0][i]
                similarity = 1 - distance  # 余弦距离转相似度

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
        # [优化] 构建更精准的查询文本
        query_parts = []

        # 1. 技术栈
        tech_stack = features.get("tech_stack", [])
        if tech_stack:
            query_parts.append(f"技术: {', '.join(tech_stack)}")

        # 2. 输入向量 - 重点标注漏洞入口
        input_vectors = features.get("input_vectors", [])
        if input_vectors:
            # 提取输入类型（如 GET, POST）
            input_types = set()
            for iv in input_vectors:
                if ":" in str(iv):
                    input_types.add(str(iv).split(":")[0])
            if input_types:
                query_parts.append(f"输入类型: {', '.join(input_types)}")
            query_parts.append(f"参数: {', '.join(str(v) for v in input_vectors)}")

        # 3. 敏感路径
        paths = features.get("sensitive_paths", [])
        if paths:
            query_parts.append(f"敏感路径: {', '.join(paths[:5])}")

        # 4. 标签
        tags = features.get("tags", [])
        if tags:
            query_parts.append(f"漏洞类型: {', '.join(tags)}")

        # 5. 从分析兵情报中提取关键信息
        # 这部分会在 innovator_node 中传入更丰富的上下文

        query = " | ".join(query_parts) if query_parts else "CTF Web 漏洞"

        print(f"   🔎 RAG查询: {query[:100]}...")
        return self.search_by_text(query, top_k)

    def search_by_tags(self, tags: List[str], top_k: int = TOP_K_RESULTS) -> List[Dict]:
        """
        根据tags检索（精确匹配）
        """
        # 确保客户端可用
        self._ensure_client_alive()

        # 先通过metadata过滤
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


# 全局单例（避免重复加载模型）
_retriever = None


def get_retriever() -> WriteupRetriever:
    """获取检索器实例（单例模式）"""
    global _retriever
    if _retriever is None:
        _retriever = WriteupRetriever()
    return _retriever


# 简单测试
if __name__ == "__main__":
    retriever = get_retriever()

    # 测试搜索
    results = retriever.search_by_text("SQL注入 报错注入")
    print(f"\n找到 {len(results)} 条结果")
    for r in results[:3]:
        print(f"  - {r['metadata']['filename']} (相似度: {r['similarity']})")
        print(f"    tags: {r['metadata'].get('tags', [])}")