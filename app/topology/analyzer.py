# topology/analyzer.py - 图分析算法

import networkx as nx
from typing import List, Optional, Dict, Set, Tuple
import heapq


class TopologyAnalyzer:
    """图分析器 - 提供多种图分析算法用于决策支持"""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    # =========================================================================
    # 路径分析
    # =========================================================================

    def find_shortest_attack_path(self, start: str, targets: List[str]) -> Optional[List[str]]:
        """
        使用Dijkstra算法找到从起点到任一目标的最短攻击路径

        Args:
            start: 起始节点
            targets: 目标节点列表

        Returns:
            最短路径节点列表，无路径返回None
        """
        best_path = None
        min_length = float('inf')

        for target in targets:
            try:
                length = nx.shortest_path_length(self.graph, start, target, weight='weight')
                if length < min_length:
                    path = nx.shortest_path(self.graph, start, target, weight='weight')
                    best_path = path
                    min_length = length
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

        return best_path

    def find_all_attack_paths(self, start: str, targets: List[str], max_depth: int = 5) -> List[List[str]]:
        """
        找到所有可能的攻击路径（限制深度防止爆炸）

        Args:
            start: 起始节点
            targets: 目标节点列表
            max_depth: 最大路径深度

        Returns:
            路径列表，按路径长度排序
        """
        target_set = set(targets)
        paths = []

        def dfs(node: str, path: List[str], visited: Set[str]):
            if len(path) > max_depth:
                return
            if node in target_set:
                paths.append(path.copy())
                return
            for neighbor in self.graph.successors(node):
                if neighbor not in visited:
                    visited.add(neighbor)
                    dfs(neighbor, path + [neighbor], visited)
                    visited.remove(neighbor)

        dfs(start, [start], {start})
        return sorted(paths, key=len)

    def get_attack_surface(self, node: str) -> List[str]:
        """
        获取某节点的攻击面（所有可达的邻居节点）

        Args:
            node: 节点URL

        Returns:
            可达节点列表
        """
        try:
            return list(self.graph.successors(node))
        except nx.NetworkXError:
            return []

    # =========================================================================
    # 关键节点识别
    # =========================================================================

    def find_critical_nodes(self, top_k: int = 3) -> List[str]:
        """
        识别关键节点（PageRank中心性）
        这些节点可能是登录页、上传点等枢纽

        Args:
            top_k: 返回top k个关键节点

        Returns:
            关键节点URL列表
        """
        try:
            if self.graph.number_of_nodes() == 0:
                return []
            pagerank = nx.pagerank(self.graph)
            critical = heapq.nlargest(top_k, pagerank.items(), key=lambda x: x[1])
            return [node for node, score in critical]
        except Exception:
            return []

    def find_hubs(self) -> List[str]:
        """
        找到枢纽节点（出度高的节点）
        这些页面包含大量链接，适合作为探索起点

        Returns:
            枢纽节点列表
        """
        out_degrees = dict(self.graph.out_degree())
        if not out_degrees:
            return []
        avg_degree = sum(out_degrees.values()) / len(out_degrees)
        hubs = [node for node, degree in out_degrees.items() if degree > avg_degree]
        return hubs

    def find_authority_nodes(self) -> List[str]:
        """
        找到权威节点（入度高的节点）
        这些页面被很多其他页面链接，可能是重要内容

        Returns:
            权威节点列表
        """
        in_degrees = dict(self.graph.in_degree())
        if not in_degrees:
            return []
        avg_degree = sum(in_degrees.values()) / len(in_degrees)
        authorities = [node for node, degree in in_degrees.items() if degree > avg_degree]
        return authorities

    # =========================================================================
    # 决策支持方法
    # =========================================================================

    def prioritize_attack_targets(self, visited: List[str], top_k: int = 5) -> List[Tuple[str, float]]:
        """
        计算攻击优先级

        综合考虑：
        1. PageRank分数（重要性）
        2. 是否未访问
        3. 节点类型（敏感路径优先）

        Args:
            visited: 已访问节点列表
            top_k: 返回top k个优先目标

        Returns:
            [(node, priority_score), ...] 按优先级排序
        """
        visited_set = set(visited)
        priorities = {}

        try:
            pagerank = nx.pagerank(self.graph)
        except Exception:
            pagerank = {n: 1.0 for n in self.graph.nodes()}

        # 敏感关键词
        sensitive_keywords = ['login', 'admin', 'upload', 'api', 'config', 'backup', 'test', 'dev']

        for node in self.graph.nodes():
            if node in visited_set:
                continue

            score = pagerank.get(node, 0.5)

            # 敏感路径加分
            for kw in sensitive_keywords:
                if kw in node.lower():
                    score *= 1.5
                    break

            # 枢纽节点加分
            out_degree = self.graph.out_degree(node)
            if out_degree > 2:
                score *= 1.2

            priorities[node] = score

        return heapq.nlargest(top_k, priorities.items(), key=lambda x: x[1])

    def find_unvisited_high_value_nodes(self, visited: List[str], top_k: int = 5) -> List[str]:
        """
        找出未访问的高价值节点

        Args:
            visited: 已访问节点列表
            top_k: 返回数量

        Returns:
            高价值节点URL列表
        """
        prioritized = self.prioritize_attack_targets(visited, top_k)
        return [node for node, _ in prioritized]

    def should_explore_more(self, visited: List[str], threshold: float = 0.3) -> bool:
        """
        判断是否应该继续探索

        Args:
            visited: 已访问节点列表
            threshold: 未访问高价值节点比例阈值

        Returns:
            True 表示还有值得探索的内容
        """
        total_nodes = self.graph.number_of_nodes()
        if total_nodes == 0:
            return False

        visited_set = set(visited)
        unvisited_ratio = (total_nodes - len(visited_set)) / total_nodes

        # 如果还有大量未访问节点，继续探索
        if unvisited_ratio > threshold:
            return True

        # 检查是否还有高价值未访问节点
        high_value = self.find_unvisited_high_value_nodes(visited, top_k=3)
        return len(high_value) > 0

    # =========================================================================
    # 循环检测
    # =========================================================================

    def detect_cycles(self) -> List[List[str]]:
        """
        检测循环路径（防止死循环）

        Returns:
            所有循环路径列表
        """
        try:
            cycles = list(nx.simple_cycles(self.graph))
            return cycles
        except Exception:
            return []

    def has_cycle(self) -> bool:
        """检查图中是否存在循环"""
        try:
            return not nx.is_directed_acyclic_graph(self.graph)
        except Exception:
            return False

    # =========================================================================
    # 统计信息
    # =========================================================================

    def get_stats(self) -> Dict:
        """
        获取图的统计信息

        Returns:
            统计数据字典
        """
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph) if self.graph.number_of_nodes() > 0 else 0,
            "avg_degree": sum(dict(self.graph.degree()).values()) / max(1, self.graph.number_of_nodes()),
            "cycles": len(self.detect_cycles()),
            "hubs": len(self.find_hubs()),
            "authorities": len(self.find_authority_nodes())
        }