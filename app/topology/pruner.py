# topology/pruner.py - 剪枝引擎


import networkx as nx
from typing import Dict, List, Set
from datetime import datetime


class TopologyPruner:
    """剪枝引擎 - 自动删除无效节点，防止死循环"""

    def __init__(self, config: Dict = None):
        self.config = config or {
            "max_depth": 5,  # 最大深度
            "dead_status_codes": [403, 404, 500],  # 死状态码
            "max_node_age": 3600,  # 节点最大存活时间（秒）
            "max_visit_count": 10,  # 最大访问次数
        }

    def prune_by_status(self, graph: nx.DiGraph, node_status: Dict[str, int]) -> nx.DiGraph:
        """
        根据状态码剪枝：删除403/404节点及其子树
        """
        G = graph.copy()
        dead_nodes = []

        for node, status in node_status.items():
            if status in self.config["dead_status_codes"]:
                dead_nodes.append(node)

        for node in dead_nodes:
            if node in G:
                # 获取所有子节点（包括间接子节点）
                descendants = list(nx.descendants(G, node))
                # 删除节点及其所有子节点
                G.remove_nodes_from([node] + descendants)
                print(f"[Pruner] 剪枝节点 {node} (status={status}) 及其 {len(descendants)} 个子节点")

        return G

    def prune_by_depth(self, graph: nx.DiGraph, root: str) -> nx.DiGraph:
        """
        按深度剪枝：删除超过最大深度的节点
        """
        G = graph.copy()

        # 计算所有节点到根节点的距离
        try:
            lengths = nx.shortest_path_length(G, root)
        except Exception:
            return G

        too_deep = []
        for node, dist in lengths.items():
            if dist > self.config["max_depth"]:
                too_deep.append(node)

        G.remove_nodes_from(too_deep)
        print(f"✂️ [Pruner] 剪枝 {len(too_deep)} 个超深节点 (>{self.config['max_depth']})")
        return G

    def prune_by_age(self, graph: nx.DiGraph, node_last_seen: Dict[str, datetime]) -> nx.DiGraph:
        """
        按时间剪枝：删除太久没访问的节点
        """
        G = graph.copy()
        now = datetime.now()
        expired = []

        for node, last_seen in node_last_seen.items():
            age = (now - last_seen).total_seconds()
            if age > self.config["max_node_age"]:
                expired.append(node)

        G.remove_nodes_from(expired)
        print(f"[Pruner] 剪枝 {len(expired)} 个过期节点")
        return G

    def prune_dead_ends(self, graph: nx.DiGraph) -> nx.DiGraph:
        """
        剪枝死胡同：删除所有没有出度的节点（除非是目标节点）
        """
        G = graph.copy()
        removed = True

        while removed:
            removed = False
            dead_ends = [n for n in G.nodes if G.out_degree(n) == 0]

            for node in dead_ends:
                # 保留可能的flag节点
                if "flag" in node or "admin" in node:
                    continue
                G.remove_node(node)
                removed = True

        return G

    def prune_all(self, graph: nx.DiGraph, metadata: Dict) -> nx.DiGraph:
        """
        综合剪枝：应用所有规则
        """
        G = graph.copy()

        # 1. 按状态码剪枝
        if "node_status" in metadata:
            G = self.prune_by_status(G, metadata["node_status"])

        # 2. 按深度剪枝
        if "root" in metadata:
            G = self.prune_by_depth(G, metadata["root"])

        # 3. 按时间剪枝
        if "node_last_seen" in metadata:
            G = self.prune_by_age(G, metadata["node_last_seen"])

        # 4. 剪枝死胡同
        G = self.prune_dead_ends(G)

        return G