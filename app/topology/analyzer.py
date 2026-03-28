# topology/analyzer.py - 图分析算法

import networkx as nx
from typing import List, Optional, Dict, Set, Tuple
from datetime import datetime
import heapq
import json
import os

# 导入错误处理模块
try:
    from self_correction import (
        with_self_correction, self_correction_manager,
        ErrorSeverity, ErrorType
    )
    SELF_CORRECTION_AVAILABLE = True
except ImportError:
    SELF_CORRECTION_AVAILABLE = False
    def with_self_correction(node_name):
        def decorator(func):
            return func
        return decorator


class TopologyAnalyzer:
    """图分析器 - 提供多种图分析算法用于决策支持"""

    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        # =========================================================================
        # 节点状态跟踪 - 用于回退机制
        # =========================================================================
        # 节点状态: "pending"|"success"|"failed"|"deprioritized"|"visited"
        self.node_status: Dict[str, str] = {}
        # 节点尝试次数
        self.node_attempts: Dict[str, int] = {}
        # 节点最后执行结果
        self.node_last_result: Dict[str, str] = {}
        # 节点最后更新时间
        self.node_last_updated: Dict[str, datetime] = {}
        # 节点优先级分数
        self.node_priority: Dict[str, float] = {}
        # 节点元数据（攻击点、漏洞信息等）
        self.node_metadata: Dict[str, Dict] = {}

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

    @with_self_correction("topology_analyzer")
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
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"识别关键节点失败: {e}",
                    severity=ErrorSeverity.LOW
                )
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

    @with_self_correction("topology_analyzer")
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
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"计算PageRank失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            pagerank = {n: 1.0 for n in self.graph.nodes()}

        try:
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
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"计算攻击优先级失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            return []

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

    @with_self_correction("topology_analyzer")
    def detect_cycles(self) -> List[List[str]]:
        """
        检测循环路径（防止死循环）

        Returns:
            所有循环路径列表
        """
        try:
            cycles = list(nx.simple_cycles(self.graph))
            return cycles
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"检测循环路径失败: {e}",
                    severity=ErrorSeverity.LOW
                )
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

    # =========================================================================
    # 节点状态管理 - 用于回退机制
    # =========================================================================

    def mark_node_success(self, node: str, metadata: Dict = None):
        """
        标记节点攻击成功

        Args:
            node: 节点URL
            metadata: 成功相关的元数据（如flag、凭据等）
        """
        self.node_status[node] = "success"
        self.node_last_updated[node] = datetime.now()
        if metadata:
            self.node_metadata[node] = metadata
        # 成功节点提高优先级（用于发现相关节点）
        self.node_priority[node] = self.node_priority.get(node, 0.5) * 1.5

    def mark_node_failed(self, node: str, reason: str = "", can_retry: bool = True):
        """
        标记节点攻击失败

        Args:
            node: 节点URL
            reason: 失败原因
            can_retry: 是否可以重试（如果可以，则降权而非标记失败）
        """
        attempts = self.node_attempts.get(node, 0) + 1
        self.node_attempts[node] = attempts

        # 如果节点可访问但有疑似攻击点，即使攻击失败也降权保留
        # 这是用户要求的降权逻辑：CTF Web节点可访问且有疑似攻击点 -> 降权
        if can_retry and attempts < 3:
            self.node_status[node] = "deprioritized"
            self.node_priority[node] = max(0.1, self.node_priority.get(node, 0.5) * 0.5)
        else:
            self.node_status[node] = "failed"
            self.node_priority[node] = 0.0

        self.node_last_result[node] = reason
        self.node_last_updated[node] = datetime.now()

    def mark_node_deprioritized(self, node: str, reason: str = ""):
        """
        标记节点降权（暂不删除，保留回退可能）

        适用场景：
        - CTF Web: 节点可访问且有疑似攻击点，但攻击失败
        - 内网: 所有主机都当成有疑似攻击点，攻击失败后降权

        Args:
            node: 节点URL
            reason: 降权原因
        """
        self.node_status[node] = "deprioritized"
        self.node_last_result[node] = reason
        self.node_last_updated[node] = datetime.now()
        # 降权但保留一定优先级，用于回退
        self.node_priority[node] = max(0.1, self.node_priority.get(node, 0.5) * 0.3)
        self.node_attempts[node] = self.node_attempts.get(node, 0) + 1

    def mark_node_visited(self, node: str, metadata: Dict = None):
        """
        标记节点已访问（但未攻击）

        Args:
            node: 节点URL
            metadata: 节点元数据（技术栈、表单等）
        """
        if node not in self.node_status:
            self.node_status[node] = "visited"
        self.node_last_updated[node] = datetime.now()
        if metadata:
            if node in self.node_metadata:
                self.node_metadata[node].update(metadata)
            else:
                self.node_metadata[node] = metadata

    def get_backtrack_candidates(self) -> List[Tuple[str, float]]:
        """
        获取可回退的候选节点（降权但可能有价值的节点）

        Returns:
            [(node, priority), ...] 按优先级排序
        """
        candidates = []
        for node, status in self.node_status.items():
            if status == "deprioritized":
                attempts = self.node_attempts.get(node, 0)
                if attempts < 3:  # 尝试次数少于3次的可以回退
                    priority = self.node_priority.get(node, 0.1)
                    candidates.append((node, priority))

        # 按优先级排序
        return sorted(candidates, key=lambda x: -x[1])

    @with_self_correction("topology_analyzer")
    def get_priority_queue(self, visited: List[str]) -> List[Tuple[str, float]]:
        """
        获取优先级队列（整合现有方法）

        优先级排序:
        1. 未访问的高价值节点（优先级最高）
        2. 可回退的降权节点（较低优先级）
        3. 已访问但未成功/失败的节点

        Args:
            visited: 已访问节点列表

        Returns:
            [(node, score), ...] 按优先级排序
        """
        try:
            visited_set = set(visited)
            candidates = []

            # 1. 未访问的高价值节点
            for node, score in self.prioritize_attack_targets(visited, top_k=20):
                status = self.node_status.get(node)
                if status not in ["success", "failed"]:
                    # 根据节点状态调整优先级
                    if status == "deprioritized":
                        score *= 0.5  # 降权节点降低优先级
                    candidates.append((node, score))

            # 2. 可回退的降权节点
            for node, priority in self.get_backtrack_candidates():
                if node not in visited_set:
                    candidates.append((node, priority * 0.8))  # 回退节点更低优先级

            # 去重并排序
            seen = set()
            unique_candidates = []
            for node, score in candidates:
                if node not in seen:
                    seen.add(node)
                    unique_candidates.append((node, score))

            return sorted(unique_candidates, key=lambda x: -x[1])
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"获取优先级队列失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            return []

    def evaluate_completion(self, found_flags: int, visited: List[str]) -> Dict:
        """
        评估任务完成度

        Args:
            found_flags: 已发现的flag数量
            visited: 已访问节点列表

        Returns:
            {
                "should_continue": bool,
                "confidence": float,
                "remaining_high_value": int,
                "unvisited_critical": List[str],
                "backtrack_available": int,
                "reasoning": str
            }
        """
        high_value = self.find_unvisited_high_value_nodes(visited)
        critical = self.find_critical_nodes()
        unvisited_critical = [n for n in critical if n not in visited]
        backtrack_candidates = self.get_backtrack_candidates()

        # 计算完成度置信度
        total_nodes = self.graph.number_of_nodes()
        visited_ratio = len(visited) / max(1, total_nodes)

        # 决策是否继续
        should_continue = (
            len(high_value) > 0 or  # 还有高价值节点
            len(unvisited_critical) > 0 or  # 还有关键节点未访问
            (found_flags == 0 and len(backtrack_candidates) > 0)  # 没找到flag但有回退候选
        )

        # 置信度计算
        if found_flags > 0:
            confidence = 0.6 + (visited_ratio * 0.4)  # 有flag时，置信度与访问率相关
        else:
            confidence = 0.3  # 没flag时置信度低

        return {
            "should_continue": should_continue,
            "confidence": confidence,
            "remaining_high_value": len(high_value),
            "unvisited_critical": unvisited_critical,
            "backtrack_available": len(backtrack_candidates),
            "visited_ratio": visited_ratio,
            "reasoning": f"剩余高价值节点: {len(high_value)}, 未访问关键节点: {len(unvisited_critical)}, 可回退节点: {len(backtrack_candidates)}"
        }

    def get_node_detail(self, node: str) -> Dict:
        """
        获取节点详细信息（用于前端展示）

        Args:
            node: 节点URL

        Returns:
            节点详细信息字典
        """
        return {
            "url": node,
            "status": self.node_status.get(node, "pending"),
            "attempts": self.node_attempts.get(node, 0),
            "last_result": self.node_last_result.get(node, ""),
            "last_updated": self.node_last_updated.get(node),
            "priority": self.node_priority.get(node, 0.5),
            "metadata": self.node_metadata.get(node, {}),
            "connections": {
                "in": list(self.graph.predecessors(node)) if node in self.graph else [],
                "out": list(self.graph.successors(node)) if node in self.graph else []
            }
        }

    def get_all_node_statuses(self) -> Dict[str, Dict]:
        """
        获取所有节点状态（用于前端展示）

        Returns:
            {node: {status, attempts, priority, ...}, ...}
        """
        result = {}
        for node in self.graph.nodes():
            result[node] = self.get_node_detail(node)
        return result

    def to_dict(self) -> Dict:
        """
        序列化为字典（用于持久化）
        """
        return {
            "node_status": self.node_status,
            "node_attempts": self.node_attempts,
            "node_last_result": self.node_last_result,
            "node_priority": self.node_priority,
            "node_metadata": self.node_metadata
        }

    def from_dict(self, data: Dict):
        """
        从字典恢复状态
        """
        self.node_status = data.get("node_status", {})
        self.node_attempts = data.get("node_attempts", {})
        self.node_last_result = data.get("node_last_result", {})
        self.node_priority = data.get("node_priority", {})
        self.node_metadata = data.get("node_metadata", {})

    # =========================================================================
    # 状态持久化方法
    # =========================================================================

    def save_state(self, filepath: str) -> bool:
        """
        保存状态到文件

        Args:
            filepath: 状态文件路径

        Returns:
            保存是否成功
        """
        try:
            data = self.to_dict()
            # 转换 datetime 为字符串
            data["node_last_updated"] = {
                k: v.isoformat() if hasattr(v, 'isoformat') else v
                for k, v in self.node_last_updated.items()
            }
            # 确保目录存在
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"保存状态失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            return False

    def load_state(self, filepath: str) -> bool:
        """
        从文件加载状态

        Args:
            filepath: 状态文件路径

        Returns:
            加载是否成功
        """
        try:
            if not os.path.exists(filepath):
                return False
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.from_dict(data)
            # 恢复 datetime
            for k, v in data.get("node_last_updated", {}).items():
                if isinstance(v, str):
                    try:
                        self.node_last_updated[k] = datetime.fromisoformat(v)
                    except ValueError:
                        pass
            return True
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_analyzer",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"加载状态失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            return False