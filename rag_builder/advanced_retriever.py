# rag_builder/advanced_retriever.py - 高级RAG检索器
# 实现先进检索策略：混合检索、查询增强、重排序、MMR多样性

import re
import os
from typing import List, Dict, Tuple, Optional
from collections import Counter

# Optional dependencies
try:
    from sentence_transformers import SentenceTransformer, CrossEncoder
    ADVANCED_RAG_AVAILABLE = True
except ImportError:
    SentenceTransformer = None
    CrossEncoder = None
    ADVANCED_RAG_AVAILABLE = False

from rag_builder.config import (
    CHROMA_DIR, EMBEDDING_MODEL, SIMILARITY_THRESHOLD,
    TOP_K_RESULTS, MAX_CONTENT_LENGTH
)

try:
    import chromadb
    CHROMADB_AVAILABLE = True
except ImportError:
    chromadb = None
    CHROMADB_AVAILABLE = False


class QueryEnhancer:
    """
    查询增强器 - 极简版

    设计原则：
    1. 不做语义扩展，避免稀释原始查询意图
    2. 只做必要的标准化（CVE格式、大小写）
    3. 让原始查询主导检索
    """

    # CVE关键词提取模式
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def enhance(self, query: str, context: Dict = None) -> List[str]:
        """
        查询增强：极简版，不做语义扩展

        Args:
            query: 原始查询
            context: 可选上下文（由AI提供）

        Returns:
            查询列表（原始查询 + 可能的标准化变体）
        """
        queries = [query]  # 原始查询始终放在第一位

        # 1. CVE编号标准化（只做格式修正）
        cve_matches = self.CVE_PATTERN.findall(query)
        if cve_matches:
            for cve in cve_matches:
                standardized = cve.upper()
                if standardized != cve:
                    queries.append(standardized)

        # 不做任何语义扩展！
        # 让原始查询主导，语义检索会自然找到相关内容

        return queries[:2]  # 最多2个查询（原始 + CVE标准化）

    def extract_key_terms(self, query: str) -> Dict[str, List[str]]:
        """提取关键术语（仅用于精确匹配，不做扩展）"""
        result = {
            "cves": self.CVE_PATTERN.findall(query),
            "keywords": []
        }

        # 只提取CVE，不做其他关键词提取
        # 语义检索会自动处理关键词

        return result


class HybridSearcher:
    """混合检索器 - BM25关键词 + 向量语义检索"""

    def __init__(self, collection):
        self.collection = collection

    def bm25_search(self, query: str, top_k: int = 10) -> List[Dict]:
        """
        BM25关键词检索（使用ChromaDB的全文搜索）

        ChromaDB不直接支持BM25，但我们可以用关键词匹配模拟
        """
        try:
            # 使用query_texts进行关键词检索
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k,
                include=["documents", "metadatas", "distances"]
            )

            formatted = []
            if results['ids'][0]:
                for i in range(len(results['ids'][0])):
                    formatted.append({
                        "id": results['ids'][0][i],
                        "content": results['documents'][0][i],
                        "metadata": results['metadatas'][0][i],
                        "distance": results['distances'][0][i],
                        "bm25_score": 1.0  # 标记为关键词检索来源
                    })
            return formatted
        except Exception as e:
            print(f"[RAG] BM25 search failed: {e}")
            return []

    def keyword_filter(self, query: str, collection, top_k: int = 20) -> List[Dict]:
        """
        关键词过滤检索 - 使用metadata过滤

        只用CVE编号进行精确过滤，不使用模糊关键词匹配
        """
        key_terms = QueryEnhancer().extract_key_terms(query)

        # 只用CVE过滤，不用模糊关键词
        if not key_terms["cves"]:
            return []

        where_conditions = []
        for cve in key_terms["cves"]:
            where_conditions.append({"cve_id": {"$contains": cve}})

        where_clause = {"$or": where_conditions}

        try:
            results = collection.get(
                where=where_clause,
                limit=top_k,
                include=["documents", "metadatas"]
            )

            formatted = []
            if results['ids']:
                for i in range(len(results['ids'])):
                    formatted.append({
                        "id": results['ids'][i],
                        "content": results['documents'][i],
                        "metadata": results['metadatas'][i],
                        "keyword_match": True,
                        "similarity": 0.8  # CVE精确匹配给一个较高相似度
                    })
            return formatted
        except Exception as e:
            print(f"[RAG] Keyword filter failed: {e}")
            return []


class Reranker:
    """重排序器 - 使用CrossEncoder精确排序"""

    # Cross-Encoder模型（更精确但更慢）
    RERANK_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    def __init__(self, use_cross_encoder: bool = False):
        self.use_cross_encoder = use_cross_encoder
        self._reranker = None

    @property
    def reranker(self):
        """延迟加载重排序模型"""
        if self._reranker is None and self.use_cross_encoder and ADVANCED_RAG_AVAILABLE:
            try:
                print("[RAG] Loading Cross-Encoder reranker...")
                self._reranker = CrossEncoder(self.RERANK_MODEL)
            except Exception as e:
                print(f"[RAG] Failed to load reranker: {e}")
                self._reranker = None
        return self._reranker

    def rerank(self, query: str, results: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        重排序检索结果

        Args:
            query: 查询文本
            results: 初步检索结果
            top_k: 返回数量

        Returns:
            重排序后的结果
        """
        if not results:
            return results

        # 使用CrossEncoder重排序（如果可用）
        if self.reranker is not None:
            try:
                # 构建query-doc对
                pairs = [(query, r.get("content", "")) for r in results]

                # 计算重排序分数
                scores = self.reranker.predict(pairs)

                # 添加分数并排序
                for i, r in enumerate(results):
                    r["rerank_score"] = float(scores[i])

                # 按重排序分数排序
                results.sort(key=lambda x: x.get("rerank_score", 0), reverse=True)

                print(f"[RAG] Reranked with CrossEncoder, best score: {results[0].get('rerank_score', 0):.3f}")

            except Exception as e:
                print(f"[RAG] Rerank failed: {e}")
                # 回退到基于相似度的排序
                results.sort(key=lambda x: x.get("similarity", x.get("rerank_score", 0)), reverse=True)
        else:
            # 基于关键词匹配质量排序
            results = self._keyword_quality_rerank(query, results)

        return results[:top_k]

    def _keyword_quality_rerank(self, query: str, results: List[Dict]) -> List[Dict]:
        """
        关键词质量重排序（无CrossEncoder时的备选方案）

        根据查询关键词在文档中的出现频率和位置评估质量
        """
        query_keywords = set(re.findall(r'\b[a-z]{3,}\b', query.lower()))
        query_keywords = {kw for kw in query_keywords if kw not in ["the", "and", "for", "with"]}

        for r in results:
            content = r.get("content", "").lower()
            metadata = r.get("metadata", {})

            # 计算关键词覆盖得分
            keyword_hits = sum(1 for kw in query_keywords if kw in content)
            keyword_coverage = keyword_hits / len(query_keywords) if query_keywords else 0

            # 计算metadata匹配得分
            meta_score = 0
            for key, value in metadata.items():
                if isinstance(value, str):
                    if any(kw in value.lower() for kw in query_keywords):
                        meta_score += 0.1

            # 综合得分
            base_sim = r.get("similarity", 0.5)
            r["quality_score"] = base_sim * 0.6 + keyword_coverage * 0.3 + min(meta_score, 0.1)

        results.sort(key=lambda x: x.get("quality_score", 0), reverse=True)
        return results


class MMRSelector:
    """MMR多样性选择器 - Maximal Marginal Relevance"""

    def __init__(self, lambda_param: float = 0.7):
        """
        Args:
            lambda_param: 相关性与多样性的平衡参数 (0-1)
                          1 = 只考虑相关性，0 = 只考虑多样性
        """
        self.lambda_param = lambda_param

    def select(self, results: List[Dict], top_k: int = 5) -> List[Dict]:
        """
        MMR选择：选择与查询相关但彼此不同的结果

        避免返回多个内容非常相似的文档
        """
        if len(results) <= top_k:
            return results

        selected = []
        remaining = results.copy()

        # 第一个选择相关性最高的
        remaining.sort(key=lambda x: x.get("similarity", x.get("quality_score", 0)), reverse=True)
        selected.append(remaining[0])
        remaining = remaining[1:]

        # 逐步选择
        while len(selected) < top_k and remaining:
            best_score = -1
            best_idx = 0

            for i, candidate in enumerate(remaining):
                # 相关性分数
                relevance = candidate.get("similarity", candidate.get("quality_score", 0))

                # 与已选结果的相似度惩罚（多样性）
                max_sim_to_selected = 0
                for s in selected:
                    sim = self._content_similarity(
                        candidate.get("content", ""),
                        s.get("content", "")
                    )
                    max_sim_to_selected = max(max_sim_to_selected, sim)

                # MMR得分
                mmr_score = self.lambda_param * relevance - (1 - self.lambda_param) * max_sim_to_selected

                if mmr_score > best_score:
                    best_score = mmr_score
                    best_idx = i

            selected.append(remaining[best_idx])
            remaining = remaining[best_idx + 1:]

        return selected

    def _content_similarity(self, content1: str, content2: str) -> float:
        """
        简单的内容相似度计算（基于关键词重叠）
        """
        words1 = set(content1.lower().split())
        words2 = set(content2.lower().split())

        # 去除常见词
        stop_words = {"the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "of", "is", "are"}
        words1 = words1 - stop_words
        words2 = words2 - stop_words

        if not words1 or not words2:
            return 0

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0


class AdvancedRetriever:
    """高级检索器 - 整合所有先进策略"""

    def __init__(self, use_reranker: bool = False):
        """
        Args:
            use_reranker: 是否使用CrossEncoder重排序（需要额外模型）
        """
        print("[RAG] Initializing Advanced Retriever...")

        if not CHROMADB_AVAILABLE:
            raise ImportError("chromadb not available")

        self.client = chromadb.PersistentClient(path=str(CHROMA_DIR))

        # 获取collections
        try:
            self.writeups_collection = self.client.get_collection("ctf_writeups")
        except:
            self.writeups_collection = None

        try:
            self.nuclei_collection = self.client.get_collection("nuclei_templates")
        except:
            self.nuclei_collection = None

        try:
            self.payloads_collection = self.client.get_collection("payloads")
        except:
            self.payloads_collection = None

        try:
            self.security_resources_collection = self.client.get_collection("security_resources")
        except:
            self.security_resources_collection = None

        # 初始化组件
        self.query_enhancer = QueryEnhancer()
        self.reranker = Reranker(use_cross_encoder=use_reranker)
        self.mmr_selector = MMRSelector(lambda_param=0.7)

        # 嵌入模型延迟加载
        self._model = None

        # 统计
        total = sum(c.count() if c else 0 for c in [
            self.writeups_collection, self.nuclei_collection,
            self.payloads_collection, self.security_resources_collection
        ])
        print(f"[RAG] Advanced Retriever ready, {total} records")

    @property
    def model(self):
        """延迟加载嵌入模型"""
        if self._model is None:
            print("[RAG] Loading embedding model...")
            self._model = SentenceTransformer(EMBEDDING_MODEL)
        return self._model

    def search(self, query: str, top_k: int = 5, sources: List[str] = None) -> Dict:
        """
        高级检索

        Args:
            query: 查询文本
            top_k: 返回数量
            sources: 数据源

        Returns:
            {"writeups": [...], "nuclei": [...], "payloads": [...], "security_resources": [...]}
        """
        sources = sources or ["writeups", "nuclei", "payloads", "security_resources"]

        # 1. 查询增强
        enhanced_queries = self.query_enhancer.enhance(query)
        print(f"[RAG] Enhanced queries: {len(enhanced_queries)}")

        results = {"total": 0}

        # 2. 对每个数据源进行检索
        for source in sources:
            collection = self._get_collection(source)
            if not collection:
                continue

            # 混合检索：向量 + 关键词
            # 获取更多候选，让后续过滤和排序有更多选择
            source_results = self._hybrid_search(
                enhanced_queries, collection, max(top_k * 3, 20)  # 至少获取20个候选
            )

            # 3. 重排序
            if source_results:
                source_results = self.reranker.rerank(query, source_results, top_k * 2)

            # 4. MMR多样性选择
            if source_results:
                source_results = self.mmr_selector.select(source_results, top_k)

            # 5. 最终过滤
            source_results = [
                r for r in source_results
                if r.get("similarity", r.get("quality_score", 0)) >= SIMILARITY_THRESHOLD
            ]

            results[source] = source_results
            results["total"] += len(source_results)

        # 打印检索质量报告
        self._print_quality_report(query, results)

        return results

    def _get_collection(self, source: str):
        """获取对应collection"""
        mapping = {
            "writeups": self.writeups_collection,
            "nuclei": self.nuclei_collection,
            "payloads": self.payloads_collection,
            "security_resources": self.security_resources_collection
        }
        return mapping.get(source)

    def _hybrid_search(self, queries: List[str], collection, top_k: int) -> List[Dict]:
        """
        混合检索：多查询向量检索 + 关键词过滤
        """
        all_results = []
        seen_ids = set()

        # 多查询向量检索
        for q in queries:
            embedding = self.model.encode(q).tolist()
            try:
                results = collection.query(
                    query_embeddings=[embedding],
                    n_results=top_k,
                    include=["documents", "metadatas", "distances"]
                )

                if results['ids'][0]:
                    for i in range(len(results['ids'][0])):
                        id_ = results['ids'][0][i]
                        if id_ not in seen_ids:
                            distance = results['distances'][0][i]
                            similarity = 1 - distance

                            all_results.append({
                                "id": id_,
                                "content": results['documents'][0][i],
                                "metadata": results['metadatas'][0][i],
                                "similarity": round(similarity, 3),
                                "query": q  # 记录来源查询
                            })
                            seen_ids.add(id_)
            except Exception as e:
                pass

        # 关键词过滤补充（仅CVE精确匹配）
        hybrid = HybridSearcher(collection)
        key_terms = self.query_enhancer.extract_key_terms(queries[0])

        if key_terms["cves"]:
            kw_results = hybrid.keyword_filter(queries[0], collection, top_k)
            for r in kw_results:
                if r["id"] not in seen_ids:
                    all_results.append(r)
                    seen_ids.add(r["id"])

        return all_results

    def _print_quality_report(self, query: str, results: Dict):
        """打印检索质量报告"""
        total = results.get("total", 0)
        if total == 0:
            print(f"[RAG] ⚠️ No results for '{query[:30]}...' (threshold={SIMILARITY_THRESHOLD})")
            return

        # 计算平均相似度
        all_items = []
        for source in ["writeups", "nuclei", "payloads", "security_resources"]:
            if source in results:
                all_items.extend(results[source])

        if all_items:
            avg_sim = sum(r.get("similarity", r.get("quality_score", 0)) for r in all_items) / len(all_items)
            max_sim = max(r.get("similarity", r.get("quality_score", 0)) for r in all_items)

            print(f"[RAG] ✓ Query '{query[:30]}...'")
            print(f"     Total: {total} results, Avg similarity: {avg_sim:.2f}, Best: {max_sim:.2f}")

            # 打印各来源结果数
            for source in ["writeups", "nuclei", "payloads", "security_resources"]:
                count = len(results.get(source, []))
                if count > 0:
                    print(f"     - {source}: {count}")


# 全局实例
_advanced_retriever = None

def get_advanced_retriever(use_reranker: bool = False) -> AdvancedRetriever:
    """获取高级检索器实例"""
    global _advanced_retriever

    if _advanced_retriever is None:
        try:
            _advanced_retriever = AdvancedRetriever(use_reranker=use_reranker)
        except Exception as e:
            print(f"[RAG] Failed to init advanced retriever: {e}")
            return None

    return _advanced_retriever


def advanced_search(query: str, top_k: int = 5, sources: List[str] = None,
                    use_reranker: bool = False) -> List[Dict]:
    """
    高级检索入口函数

    Args:
        query: 查询文本
        top_k: 返回数量
        sources: 数据源列表
        use_reranker: 是否使用CrossEncoder重排序

    Returns:
        检索结果列表
    """
    retriever = get_advanced_retriever(use_reranker=use_reranker)

    if retriever is None:
        # 回退到基础检索
        from rag_builder.retriever import retrieve_relevant_knowledge
        return retrieve_relevant_knowledge(query, sources=sources, top_k=top_k)

    raw_results = retriever.search(query, top_k=top_k, sources=sources)

    # 合并结果
    all_results = []
    for source in (sources or ["writeups", "nuclei", "payloads", "security_resources"]):
        if source in raw_results:
            for item in raw_results[source]:
                item["source"] = source
                all_results.append(item)

    # 按相似度排序
    all_results.sort(key=lambda x: x.get("similarity", x.get("quality_score", 0)), reverse=True)

    return all_results[:top_k]


# 测试
if __name__ == "__main__":
    print("\n--- Testing Advanced RAG ---")

    # 测试查询增强
    enhancer = QueryEnhancer()
    test_queries = [
        "SQL injection bypass WAF",
        "CVE-2023-44487",
        "Spring SSTI exploit",
    ]

    for q in test_queries:
        enhanced = enhancer.enhance(q)
        print(f"\nQuery: {q}")
        print(f"Enhanced: {enhanced}")
        print(f"Key terms: {enhancer.extract_key_terms(q)}")