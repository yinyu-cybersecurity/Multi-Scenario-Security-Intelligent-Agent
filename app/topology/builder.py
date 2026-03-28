# topology/builder.py - 拓扑图构建器

import networkx as nx
import os
import json
import time
import hashlib
import traceback
from typing import Dict, List, Optional

# 导入自我纠错模块
try:
    from app.self_correction import self_correction_manager, ErrorSeverity, ErrorType
except ImportError:
    from self_correction import self_correction_manager, ErrorSeverity, ErrorType


class TopologyBuilder:
    """图构建器 - 将邻接表转为NetworkX图"""

    def __init__(self):
        self.node_attrs = {}  # 存储节点属性的临时字典
        self.graph = None     # 缓存的图对象
        self._cache_version = 0  # 缓存版本号
        self._last_adj_hash = None  # 上次邻接表的哈希

    def add_node_attr(self, url: str, **attrs):
        """
        添加节点属性

        Args:
            url: 节点URL
            **attrs: 属性键值对（如 status_code=200）
        """
        if url not in self.node_attrs:
            self.node_attrs[url] = {}
        self.node_attrs[url].update(attrs)

    def build_from_adjacency(self, adj: Dict[str, List[str]], metadata: Dict[str, Dict] = None) -> nx.DiGraph:
        """
        从邻接表构建图

        Args:
            adj: 邻接表字典
            metadata: 节点属性字典 {url: {attr: val}}
        """
        # 计算邻接表哈希，检测变化
        try:
            adj_hash = hashlib.md5(str(sorted(adj.items())).encode()).hexdigest()
        except Exception:
            adj_hash = None

        if self.graph is not None and adj_hash is not None and adj_hash == self._last_adj_hash:
            # 邻接表未变化，返回缓存
            return self.graph

        G = nx.DiGraph()

        for src, targets in adj.items():
            if src not in G:
                G.add_node(src)
            for tgt in targets:
                if tgt not in G:
                    G.add_node(tgt)
                G.add_edge(src, tgt)

        # 合并节点属性
        if metadata:
            nx.set_node_attributes(G, metadata)

        self.graph = G
        self._last_adj_hash = adj_hash
        self._cache_version += 1
        return G

    def update_from_explorer(self, state: Dict, new_paths: Dict[str, List[str]]) -> Dict:
        """
        探索兵发现新路径时调用此方法更新拓扑
        """
        adj = state.get("site_topology", {})
        meta = state.get("node_metadata", {})

        for src, targets in new_paths.items():
            if src not in adj:
                adj[src] = []
            for tgt in targets:
                if tgt not in adj[src]:
                    adj[src].append(tgt)

        # 更新当前节点的 metadata
        if "page_features" in state:
            features = state["page_features"]
            url = state.get("current_url")
            if url:
                if url not in meta:
                    meta[url] = {}
                meta[url].update({
                    "tech_stack": features.get("tech_stack", []),
                    "forms_count": len(features.get("form_structure", [])),
                    "status": 200,
                    "last_seen": time.time()
                })

        # 清除缓存的图和哈希
        self.graph = None
        self._last_adj_hash = None

        return {
            "site_topology": adj,
            "node_metadata": meta
        }

    # =========================================================================
    # 持久化功能
    # =========================================================================

    def save(self, path: str, adj: Dict[str, List[str]], metadata: Dict[str, Dict] = None):
        """
        保存拓扑到文件

        Args:
            path: 文件路径 (.gpickle 或 .json)
            adj: 邻接表
            metadata: 节点元数据
        """
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)

            # 构建图
            G = self.build_from_adjacency(adj, metadata)

            if path.endswith('.gpickle'):
                # 二进制格式，效率更高
                nx.write_gpickle(G, path)
            elif path.endswith('.json'):
                # JSON格式，可读性好
                data = {
                    "adjacency": adj,
                    "metadata": metadata or {},
                    "stats": {
                        "nodes": G.number_of_nodes(),
                        "edges": G.number_of_edges(),
                        "saved_at": time.time()
                    }
                }
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                raise ValueError("Unsupported format. Use .gpickle or .json")
        except Exception as e:
            # 记录错误
            self_correction_manager.record_error(
                node="TopologyBuilder.save",
                error_type=ErrorType.EXECUTION_ERROR,
                error_message=f"保存拓扑文件失败: {str(e)}",
                severity=ErrorSeverity.MEDIUM
            )
            raise

    def load(self, path: str) -> Dict:
        """
        从文件加载拓扑

        Args:
            path: 文件路径

        Returns:
            {"adjacency": dict, "metadata": dict}
        """
        try:
            if not os.path.exists(path):
                return {"adjacency": {}, "metadata": {}}

            if path.endswith('.gpickle'):
                G = nx.read_gpickle(path)
                # 转换为邻接表
                adj = {n: list(G.successors(n)) for n in G.nodes()}
                metadata = dict(G.nodes(data=True))
                self.graph = G
                # 更新缓存哈希
                try:
                    self._last_adj_hash = hashlib.md5(str(sorted(adj.items())).encode()).hexdigest()
                except Exception:
                    pass
                self._cache_version += 1
                return {"adjacency": adj, "metadata": metadata}

            elif path.endswith('.json'):
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return {
                    "adjacency": data.get("adjacency", {}),
                    "metadata": data.get("metadata", {})
                }

            raise ValueError("Unsupported format. Use .gpickle or .json")
        except Exception as e:
            # 记录错误
            self_correction_manager.record_error(
                node="TopologyBuilder.load",
                error_type=ErrorType.EXECUTION_ERROR,
                error_message=f"加载拓扑文件失败: {str(e)}",
                severity=ErrorSeverity.MEDIUM
            )
            raise

    def get_or_build_graph(self, adj: Dict[str, List[str]], metadata: Dict[str, Dict] = None) -> nx.DiGraph:
        """获取或构建图对象（带缓存和哈希验证）"""
        if self.graph is not None:
            # 验证邻接表是否变化
            try:
                adj_hash = hashlib.md5(str(sorted(adj.items())).encode()).hexdigest()
                if adj_hash == self._last_adj_hash:
                    return self.graph
            except Exception:
                pass
        return self.build_from_adjacency(adj, metadata)

    def set_edge_weights(self, weight_func=None):
        """
        设置边权重

        Args:
            weight_func: 权重计算函数 (source, target, attrs) -> weight
                        默认根据目标节点属性计算
        """
        if self.graph is None:
            return

        for u, v, data in self.graph.edges(data=True):
            if weight_func:
                data['weight'] = weight_func(u, v, data)
            else:
                # 默认权重：基于目标节点属性
                target_attrs = self.graph.nodes.get(v, {})
                weight = 1.0

                # 状态码影响
                status = target_attrs.get('status', 200)
                if status == 200:
                    weight *= 0.5  # 可访问优先
                elif status in [403, 404, 500]:
                    weight *= 2.0  # 错误页面降低优先级

                # 敏感路径优先
                sensitive_keywords = ['login', 'admin', 'upload', 'api', 'config']
                if any(kw in v.lower() for kw in sensitive_keywords):
                    weight *= 0.3

                data['weight'] = weight


def get_topology_path(task_name: str, base_dir: str = "/tmp/ctf_topology") -> str:
    """获取拓扑文件路径"""
    os.makedirs(base_dir, exist_ok=True)
    safe_name = task_name.replace('/', '_').replace(':', '_')
    return os.path.join(base_dir, f"{safe_name}.json")