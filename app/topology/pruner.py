# topology/pruner.py - 剪枝引擎


import os
import networkx as nx
from typing import Dict, List, Set, Optional
from datetime import datetime
from logger import get_logger

logger = get_logger("Pruner")

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


class TopologyPruner:
    """剪枝引擎 - 智能降权与节点管理

    改进：
    - 不直接删除节点，而是降权保留
    - 支持回退机制
    - 区分不同场景的降权策略
    """

    def __init__(self, config: Dict = None):
        self.config = config or {
            "max_depth": 5,  # 最大深度
            "dead_status_codes": [403, 404, 500],  # 死状态码
            "max_node_age": 3600,  # 节点最大存活时间（秒）
            "max_visit_count": 10,  # 最大访问次数
            "max_attempts": 3,  # 最大尝试次数（超过后才真正删除）
        }
        # 降权节点存储（用于回退）
        self.deprioritized_nodes: Dict[str, Dict] = {}
        # 已删除节点存储（用于恢复）
        self.removed_nodes: Dict[str, Dict] = {}

    def prune_by_status(self, graph: nx.DiGraph, node_status: Dict[str, int],
                        analyzer: Optional['TopologyAnalyzer'] = None) -> nx.DiGraph:
        """
        根据状态码剪枝：降权而非直接删除

        改进：
        - 对于403/404/500状态码，先降权标记
        - 只有尝试次数超过阈值才真正删除
        - 保留疑似攻击点的节点（如200但有攻击失败）

        Args:
            graph: 原图
            node_status: 节点状态码映射
            analyzer: 拓扑分析器实例（可选，用于同步状态）

        Returns:
            剪枝后的图
        """
        G = graph.copy()

        try:
            for node, status in node_status.items():
                if status in self.config["dead_status_codes"]:
                    # 记录到降权列表
                    self.deprioritized_nodes[node] = {
                        "status": status,
                        "reason": f"HTTP {status}",
                        "timestamp": datetime.now().isoformat(),
                        "can_backtrack": True
                    }

                    # 同步到分析器
                    if analyzer:
                        analyzer.mark_node_deprioritized(node, f"HTTP {status}")

                    # 检查尝试次数，决定是否真正删除
                    attempts = 0
                    if analyzer and hasattr(analyzer, 'node_attempts'):
                        attempts = analyzer.node_attempts.get(node, 0)
                    if attempts >= self.config["max_attempts"]:
                        # 超过最大尝试次数，从图中移除
                        if node in G:
                            try:
                                descendants = list(nx.descendants(G, node))
                                G.remove_nodes_from([node] + descendants)
                                self.removed_nodes[node] = {
                                    "status": status,
                                    "descendants": descendants,
                                    "timestamp": datetime.now().isoformat()
                                }
                                logger.info(f"删除节点 {node} (status={status}, attempts={attempts}) 及其 {len(descendants)} 个子节点")
                            except nx.NetworkXError:
                                pass
                    else:
                        # 降权但保留
                        logger.info(f"降权节点 {node} (status={status}, attempts={attempts})")
                else:
                    # 状态码正常（如200），但有攻击失败的情况
                    # 检查分析器中是否有攻击失败的记录
                    if analyzer and hasattr(analyzer, 'node_status') and analyzer.node_status.get(node) == "deprioritized":
                        # 节点可访问但攻击失败 -> 降权保留
                        if node not in self.deprioritized_nodes:
                            self.deprioritized_nodes[node] = {
                                "status": status,
                                "reason": "attack_failed_but_accessible",
                                "timestamp": datetime.now().isoformat(),
                                "can_backtrack": True,
                                "has_attack_point": True  # 标记有疑似攻击点
                            }
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_pruner",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"prune_by_status 失败: {e}",
                    severity=ErrorSeverity.MEDIUM
                )
            logger.warning(f"prune_by_status 异常: {e}")

        return G

    def prune_by_depth(self, graph: nx.DiGraph, root: str) -> nx.DiGraph:
        """
        按深度剪枝：删除超过最大深度的节点
        """
        G = graph.copy()

        try:
            # 计算所有节点到根节点的距离
            lengths = nx.shortest_path_length(G, root)
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_pruner",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"prune_by_depth 计算距离失败: {e}",
                    severity=ErrorSeverity.LOW
                )
            return G

        too_deep = []
        for node, dist in lengths.items():
            if dist > self.config["max_depth"]:
                too_deep.append(node)

        try:
            G.remove_nodes_from(too_deep)
            logger.info(f"剪枝 {len(too_deep)} 个超深节点 (>{self.config['max_depth']})")
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_pruner",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"prune_by_depth 删除节点失败: {e}",
                    severity=ErrorSeverity.LOW
                )

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
        logger.info(f"剪枝 {len(expired)} 个过期节点")
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

    @with_self_correction("prune_all")
    def prune_all(self, graph: nx.DiGraph, metadata: Dict,
                  analyzer: Optional['TopologyAnalyzer'] = None) -> nx.DiGraph:
        """
        综合剪枝：应用所有规则（智能模式）

        改进：
        - 整合分析器状态进行智能剪枝
        - 优先降权而非删除
        """
        G = graph.copy()

        try:
            # 1. 按状态码剪枝（降权）
            if "node_status" in metadata:
                G = self.prune_by_status(G, metadata["node_status"], analyzer)

            # 2. 按深度剪枝
            if "root" in metadata:
                G = self.prune_by_depth(G, metadata["root"])

            # 3. 按时间剪枝
            if "node_last_seen" in metadata:
                G = self.prune_by_age(G, metadata["node_last_seen"])

            # 4. 剪枝死胡同
            G = self.prune_dead_ends(G)

            # 5. 同步状态到分析器
            self.sync_with_analyzer(analyzer)

        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_pruner",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"prune_all 失败: {e}",
                    severity=ErrorSeverity.MEDIUM
                )
            logger.warning(f"prune_all 异常: {e}")

        return G

    def sync_with_analyzer(self, analyzer: Optional['TopologyAnalyzer'] = None):
        """同步降权节点状态到分析器"""
        if not analyzer:
            return

        try:
            for node, info in self.deprioritized_nodes.items():
                if info.get("can_backtrack", False):
                    if hasattr(analyzer, 'node_status'):
                        analyzer.node_status[node] = "deprioritized"
                    if hasattr(analyzer, 'node_priority'):
                        analyzer.node_priority[node] = 0.3  # 降权但保留
        except Exception as e:
            if SELF_CORRECTION_AVAILABLE:
                self_correction_manager.record_error(
                    node="topology_pruner",
                    error_type=ErrorType.EXECUTION_ERROR,
                    error_message=f"同步状态失败: {e}",
                    severity=ErrorSeverity.LOW
                )

    # =========================================================================
    # 回退机制
    # =========================================================================

    def get_deprioritized_nodes(self) -> Dict[str, Dict]:
        """获取被降权的节点（用于回退）"""
        return self.deprioritized_nodes

    def get_backtrack_candidates(self, analyzer: Optional['TopologyAnalyzer'] = None) -> List[str]:
        """
        获取可回退的候选节点

        筛选条件：
        - 有疑似攻击点的节点（优先）
        - 尝试次数少于阈值的节点
        """
        candidates = []

        for node, info in self.deprioritized_nodes.items():
            if info.get("can_backtrack", False):
                # 检查尝试次数
                attempts = 0
                if analyzer and hasattr(analyzer, 'node_attempts'):
                    attempts = analyzer.node_attempts.get(node, 0)
                if attempts < self.config["max_attempts"]:
                    candidates.append(node)

        # 优先返回有攻击点的节点
        has_attack_point = [n for n in candidates
                           if self.deprioritized_nodes[n].get("has_attack_point")]
        no_attack_point = [n for n in candidates
                          if not self.deprioritized_nodes[n].get("has_attack_point")]

        return has_attack_point + no_attack_point

    def restore_node(self, node: str, graph: nx.DiGraph,
                     analyzer: Optional['TopologyAnalyzer'] = None) -> bool:
        """
        回退：将降权节点恢复为可探测状态

        Args:
            node: 节点URL
            graph: 当前图（可能需要从备份恢复）
            analyzer: 拓扑分析器实例

        Returns:
            是否成功恢复
        """
        if node in self.deprioritized_nodes:
            info = self.deprioritized_nodes[node]
            del self.deprioritized_nodes[node]

            # 同步分析器状态
            if analyzer:
                if hasattr(analyzer, 'node_status'):
                    analyzer.node_status[node] = "pending"
                if hasattr(analyzer, 'node_priority'):
                    analyzer.node_priority[node] = 0.5  # 恢复默认优先级

            logger.info(f"回退节点 {node}，原因: {info.get('reason', 'unknown')}")
            return True

        return False

    def get_removed_nodes(self) -> Dict[str, Dict]:
        """获取已删除的节点"""
        return self.removed_nodes

    def get_stats(self) -> Dict:
        """获取剪枝统计信息"""
        return {
            "deprioritized_count": len(self.deprioritized_nodes),
            "removed_count": len(self.removed_nodes),
            "backtrack_available": sum(1 for n in self.deprioritized_nodes.values()
                                       if n.get("can_backtrack", False))
        }