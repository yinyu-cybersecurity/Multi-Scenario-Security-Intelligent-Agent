# topology/builder.py - 拓扑图构建器

import networkx as nx
import time
from typing import Dict, List, Optional


class TopologyBuilder:
    """图构建器 - 将邻接表转为NetworkX图"""

    def __init__(self):
        self.node_attrs = {}  # 存储节点属性的临时字典

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
        return G

    def update_from_explorer(self, state: Dict, new_paths: Dict[str, List[str]]) -> Dict:
        """
        探索兵发现新路径时调用此方法更新拓扑
        """
        adj = state.get("site_topology", {})
        meta = state.get("node_metadata", {}) # 从状态获取 metadata

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
                if url not in meta: meta[url] = {}
                meta[url].update({
                    "tech_stack": features.get("tech_stack", []),
                    "forms_count": len(features.get("form_structure", [])),
                    "status": 200,
                    "last_seen": time.time()
                })

        return {
            "site_topology": adj,
            "node_metadata": meta
        }