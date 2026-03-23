# topology/analyzer.py - 图分析算法


import networkx as nx
from typing import List, Optional
import heapq


class TopologyAnalyzer:
    """图分析器"""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def find_shortest_attack_path(self, start: str, targets: List[str]) -> Optional[List[str]]:
        """
        使用Dijkstra算法（考虑路径权重）找到从起点到任一目标的最短攻击路径
        """
        best_path = None
        min_length = float('inf')

        for target in targets:
            try:
                # 考虑路径权重（可自定义权重函数）
                length = nx.shortest_path_length(self.graph, start, target, weight='weight')
                if length < min_length:
                    path = nx.shortest_path(self.graph, start, target, weight='weight')
                    best_path = path
                    min_length = length
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return best_path

    def find_critical_nodes(self, top_k: int = 3) -> List[str]:
        """
        识别关键节点（PageRank中心性）
        这些节点可能是登录页、上传点等枢纽
        """
        try:
            pagerank = nx.pagerank(self.graph)
            # 按PageRank值排序，取top_k
            critical = heapq.nlargest(top_k, pagerank.items(), key=lambda x: x[1])
            return [node for node, score in critical]
        except:
            return []

    def detect_cycles(self) -> List[List[str]]:
        """
        检测循环路径（防止死循环）
        返回所有循环路径
        """
        try:
            cycles = list(nx.simple_cycles(self.graph))
            return cycles
        except:
            return []

    def find_hubs(self) -> List[str]:
        """
        找到枢纽节点（出度高的节点）
        这些页面包含大量链接
        """
        out_degrees = dict(self.graph.out_degree())
        # 取平均出度以上的节点
        avg_degree = sum(out_degrees.values()) / len(out_degrees) if out_degrees else 0
        hubs = [node for node, degree in out_degrees.items() if degree > avg_degree]
        return hubs