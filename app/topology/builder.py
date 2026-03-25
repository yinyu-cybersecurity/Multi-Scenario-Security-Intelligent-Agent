# topology/builder.py - 拓扑图构建器

import networkx as nx
import os
import json
import time
from typing import Dict, List, Optional


class TopologyBuilder:
    """图构建器 - 将邻接表转为NetworkX图"""

    def __init__(self):
        self.node_attrs = {}  # 存储节点属性的临时字典
        self.graph = None     # 缓存的图对象

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

        # 清除缓存的图
        self.graph = None

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

    def load(self, path: str) -> Dict:
        """
        从文件加载拓扑

        Args:
            path: 文件路径

        Returns:
            {"adjacency": dict, "metadata": dict}
        """
        if not os.path.exists(path):
            return {"adjacency": {}, "metadata": {}}

        if path.endswith('.gpickle'):
            G = nx.read_gpickle(path)
            # 转换为邻接表
            adj = {n: list(G.successors(n)) for n in G.nodes()}
            metadata = dict(G.nodes(data=True))
            self.graph = G
            return {"adjacency": adj, "metadata": metadata}

        elif path.endswith('.json'):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {
                "adjacency": data.get("adjacency", {}),
                "metadata": data.get("metadata", {})
            }

        raise ValueError("Unsupported format. Use .gpickle or .json")

    def get_or_build_graph(self, adj: Dict[str, List[str]], metadata: Dict[str, Dict] = None) -> nx.DiGraph:
        """获取或构建图对象（带缓存）"""
        if self.graph is None:
            self.graph = self.build_from_adjacency(adj, metadata)
        return self.graph

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