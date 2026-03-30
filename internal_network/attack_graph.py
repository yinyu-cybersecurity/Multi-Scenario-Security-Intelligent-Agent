# internal_network/attack_graph.py
"""
攻击图模型 - 内网渗透攻击路径建模

功能：
1. 建模主机节点和攻击路径
2. 计算攻击路径成本
3. 识别关键攻击节点
4. 支持多目标路径规划

集成：
- app.logger
- 内网渗透状态
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import heapq

# 集成日志
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

logger = get_logger("AttackGraph")


class NodeType(Enum):
    """节点类型"""
    COMPROMISED = "compromised"      # 已攻陷
    TARGET = "target"                # 目标
    PIVOT = "pivot"                  # 跳板机
    DOMAIN_CONTROLLER = "dc"         # 域控
    DATABASE = "database"            # 数据库
    WORKSTATION = "workstation"      # 工作站
    UNKNOWN = "unknown"              # 未知


class EdgeType(Enum):
    """边类型（攻击方式）"""
    SMB = "smb"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    WMI = "wmi"
    PS_EXEC = "psexec"
    KERBEROS = "kerberos"
    PASS_THE_HASH = "pth"
    UNKNOWN = "unknown"


@dataclass
class AttackNode:
    """攻击图节点"""
    id: str                           # 主机IP或标识
    node_type: NodeType
    hostname: str = ""
    os_type: str = ""                 # windows/linux
    ports: List[int] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)
    is_compromised: bool = False
    is_admin: bool = False
    credentials_available: List[str] = field(default_factory=list)  # 可用凭据
    value: int = 0                    # 资产价值
    notes: str = ""

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, AttackNode):
            return self.id == other.id
        return False


@dataclass
class AttackEdge:
    """攻击图边"""
    source: str                       # 源节点ID
    target: str                       # 目标节点ID
    edge_type: EdgeType
    credential_required: bool = False
    credential_id: str = ""
    cost: float = 1.0                 # 攻击成本（时间/风险）
    success_probability: float = 0.5  # 成功概率
    notes: str = ""


class AttackGraph:
    """
    攻击图模型

    建模内网渗透的攻击路径，支持：
    - 路径规划
    - 成本计算
    - 关键节点识别
    """

    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self.adjacency: Dict[str, List[Tuple[str, AttackEdge]]] = defaultdict(list)

    def add_node(self, node: AttackNode):
        """添加节点"""
        self.nodes[node.id] = node
        logger.debug(f"[AttackGraph] 添加节点: {node.id} ({node.node_type.value})")

    def add_edge(self, edge: AttackEdge):
        """添加边"""
        self.edges.append(edge)
        self.adjacency[edge.source].append((edge.target, edge))
        logger.debug(f"[AttackGraph] 添加边: {edge.source} -> {edge.target} ({edge.edge_type.value})")

    def get_node(self, node_id: str) -> Optional[AttackNode]:
        """获取节点"""
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[Tuple[AttackNode, AttackEdge]]:
        """获取邻居节点和边"""
        neighbors = []
        for target_id, edge in self.adjacency.get(node_id, []):
            target_node = self.nodes.get(target_id)
            if target_node:
                neighbors.append((target_node, edge))
        return neighbors

    def find_shortest_path(self, source: str, target: str) -> Tuple[List[str], float]:
        """
        找到最短攻击路径（Dijkstra算法）

        Returns:
            (路径节点列表, 总成本)
        """
        if source not in self.nodes or target not in self.nodes:
            return [], float('inf')

        # 优先队列: (成本, 节点ID, 路径)
        pq = [(0, source, [source])]
        visited = set()

        while pq:
            cost, current, path = heapq.heappop(pq)

            if current in visited:
                continue

            visited.add(current)

            if current == target:
                return path, cost

            for neighbor_id, edge in self.adjacency.get(current, []):
                if neighbor_id not in visited:
                    new_cost = cost + edge.cost
                    heapq.heappush(pq, (new_cost, neighbor_id, path + [neighbor_id]))

        return [], float('inf')

    def find_all_paths(self, source: str, target: str, max_depth: int = 5) -> List[Tuple[List[str], float]]:
        """
        找到所有攻击路径（DFS）

        Args:
            source: 起始节点
            target: 目标节点
            max_depth: 最大搜索深度

        Returns:
            [(路径, 成本), ...]
        """
        all_paths = []

        def dfs(current: str, path: List[str], cost: float, visited: Set[str]):
            if len(path) > max_depth:
                return

            if current == target:
                all_paths.append((path.copy(), cost))
                return

            for neighbor_id, edge in self.adjacency.get(current, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    path.append(neighbor_id)
                    dfs(neighbor_id, path, cost + edge.cost, visited)
                    path.pop()
                    visited.remove(neighbor_id)

        dfs(source, [source], 0, {source})

        # 按成本排序
        all_paths.sort(key=lambda x: x[1])
        return all_paths

    def find_critical_nodes(self) -> List[AttackNode]:
        """
        识别关键节点

        关键节点定义：到其他节点路径最多的节点
        """
        centrality = defaultdict(int)

        for source in self.nodes:
            for target in self.nodes:
                if source != target:
                    path, _ = self.find_shortest_path(source, target)
                    for node in path[1:-1]:  # 排除起点和终点
                        centrality[node] += 1

        # 排序
        critical = sorted(
            [self.nodes[nid] for nid in centrality],
            key=lambda n: centrality[n.id],
            reverse=True
        )

        return critical[:5]  # 返回前5个关键节点

    def calculate_attack_cost(self, path: List[str]) -> float:
        """计算攻击路径成本"""
        total_cost = 0.0

        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]

            for neighbor_id, edge in self.adjacency.get(source, []):
                if neighbor_id == target:
                    # 基础成本 + 凭据成本
                    cost = edge.cost
                    if edge.credential_required:
                        # 有凭据降低成本
                        cost *= 0.5
                    total_cost += cost
                    break

        return total_cost

    def get_recommended_targets(self, compromised_nodes: Set[str]) -> List[AttackNode]:
        """
        获取推荐攻击目标

        统一优先级计算（与TopologyAnalyzer一致）：
        1. 敏感端口加分（域控/数据库）
        2. 枢纽节点加分（连接数多）
        3. 有可用凭据加分
        4. 低攻击成本加分
        """
        targets = []

        # 计算节点连接数（枢纽性）
        connection_count = defaultdict(int)
        for edge in self.edges:
            connection_count[edge.target] += 1

        for node_id, node in self.nodes.items():
            if node_id in compromised_nodes:
                continue

            # 检查是否可达
            reachable = False
            min_cost = float('inf')
            for compromised in compromised_nodes:
                path, cost = self.find_shortest_path(compromised, node_id)
                if path:
                    reachable = True
                    min_cost = min(min_cost, cost)
                    break

            if not reachable:
                continue

            # 统一优先级计算（与TopologyAnalyzer.prioritize_attack_targets一致）
            score = node.value  # 基础价值

            # 敏感端口加分（类比Web的敏感关键词）
            sensitive_ports = {88, 389, 636, 1433, 3306, 5432, 5985, 5986}
            if any(p in node.ports for p in sensitive_ports):
                score *= 1.5

            # 枢纽节点加分（类比Web的out_degree > 2）
            if connection_count[node_id] > 2:
                score *= 1.2

            # 有凭据加分
            if node.credentials_available:
                score *= 1.3

            # 低攻击成本加分
            if min_cost < float('inf') and min_cost < 2.0:
                score *= 1.1

            targets.append((node, score))

        # 按统一优先级排序
        targets.sort(key=lambda x: x[1], reverse=True)
        return [node for node, _ in targets[:5]]

    def export_dict(self) -> Dict:
        """导出为字典格式"""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "hostname": n.hostname,
                    "os": n.os_type,
                    "ports": n.ports,
                    "compromised": n.is_compromised,
                    "admin": n.is_admin,
                    "value": n.value
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type.value,
                    "cost": e.cost,
                    "credential_required": e.credential_required
                }
                for e in self.edges
            ]
        }

    @classmethod
    def from_state(cls, state: Dict) -> "AttackGraph":
        """
        从CTFState构建攻击图

        Args:
            state: CTFState字典

        Returns:
            AttackGraph实例
        """
        graph = cls()

        # 添加已攻陷节点
        sessions = state.get("active_sessions") or []
        compromised_hosts = state.get("compromised_hosts") or []

        for session in sessions:
            host = session.get("host", "")
            if host:
                node = AttackNode(
                    id=host,
                    node_type=NodeType.COMPROMISED,
                    is_compromised=True,
                    is_admin=session.get("is_admin", False),
                    os_type=session.get("os_type", "unknown")
                )
                graph.add_node(node)

        # 添加发现的内网主机
        internal_hosts = state.get("internal_hosts") or []
        for host in internal_hosts:
            if not isinstance(host, dict):
                continue

            ip = host.get("ip", "")
            if not ip or ip in graph.nodes:
                continue

            ports = [p.get("port") for p in host.get("ports", []) if isinstance(p, dict) and p.get("port")]

            # 判断节点类型
            if any(p in ports for p in [88, 389, 636]):
                node_type = NodeType.DOMAIN_CONTROLLER
                value = 100
            elif any(p in ports for p in [1433, 3306, 5432]):
                node_type = NodeType.DATABASE
                value = 80
            elif any(p in ports for p in [22, 3389]):
                node_type = NodeType.WORKSTATION
                value = 50
            else:
                node_type = NodeType.UNKNOWN
                value = 30

            node = AttackNode(
                id=ip,
                node_type=node_type,
                ports=ports,
                value=value,
                is_compromised=ip in compromised_hosts
            )
            graph.add_node(node)

        # 添加攻击边（基于凭据和网络连通性）
        credentials = state.get("credentials") or []

        for source_node in graph.nodes.values():
            if not source_node.is_compromised:
                continue

            for target_node in graph.nodes.values():
                if target_node.id == source_node.id or target_node.is_compromised:
                    continue

                # 根据端口判断可能的攻击方式
                edge = _infer_attack_edge(source_node, target_node, credentials)
                if edge:
                    graph.add_edge(edge)

        return graph


def _infer_attack_edge(source: AttackNode, target: AttackNode,
                       credentials: List[Dict]) -> Optional[AttackEdge]:
    """
    推断可能的攻击边

    根据目标开放的端口推断攻击方式
    """
    # SMB攻击
    if 445 in target.ports:
        return AttackEdge(
            source=source.id,
            target=target.id,
            edge_type=EdgeType.SMB,
            credential_required=True,
            cost=1.0,
            success_probability=0.7
        )

    # WinRM攻击
    if 5985 in target.ports or 5986 in target.ports:
        return AttackEdge(
            source=source.id,
            target=target.id,
            edge_type=EdgeType.WINRM,
            credential_required=True,
            cost=1.2,
            success_probability=0.8
        )

    # SSH攻击
    if 22 in target.ports:
        return AttackEdge(
            source=source.id,
            target=target.id,
            edge_type=EdgeType.SSH,
            credential_required=True,
            cost=1.5,
            success_probability=0.6
        )

    # RDP攻击
    if 3389 in target.ports:
        return AttackEdge(
            source=source.id,
            target=target.id,
            edge_type=EdgeType.RDP,
            credential_required=True,
            cost=2.0,
            success_probability=0.5
        )

    return None


def build_attack_graph_from_state(state: Dict) -> AttackGraph:
    """
    从状态构建攻击图的便捷函数
    """
    return AttackGraph.from_state(state)


def get_best_attack_path(state: Dict, target_ip: str = None) -> Dict:
    """
    获取最佳攻击路径

    Args:
        state: CTFState
        target_ip: 目标IP（可选，不提供则自动选择最高价值目标）

    Returns:
        {
            "path": List[str],
            "cost": float,
            "methods": List[str],
            "target": str
        }
    """
    graph = AttackGraph.from_state(state)

    # 获取已攻陷节点
    sessions = state.get("active_sessions") or []
    compromised = {s.get("host") for s in sessions if s.get("host")}

    if not compromised:
        return {"error": "无已攻陷节点作为起点"}

    # 选择目标
    if not target_ip:
        targets = graph.get_recommended_targets(compromised)
        if not targets:
            return {"error": "无可用攻击目标"}
        target_ip = targets[0].id

    # 找最短路径
    source = list(compromised)[0]
    path, cost = graph.find_shortest_path(source, target_ip)

    if not path:
        return {"error": f"无法找到到 {target_ip} 的路径"}

    # 获取攻击方法
    methods = []
    for i in range(len(path) - 1):
        for neighbor_id, edge in graph.adjacency.get(path[i], []):
            if neighbor_id == path[i + 1]:
                methods.append(edge.edge_type.value)
                break

    return {
        "path": path,
        "cost": cost,
        "methods": methods,
        "target": target_ip
    }