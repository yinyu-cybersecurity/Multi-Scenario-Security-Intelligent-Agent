# internal_network/strategic_planner.py
"""
战略规划器节点 - AI驱动的内网渗透战略决策

作用：
1. 分析当前攻击态势
2. 规划攻击链和优先级
3. 选择最优攻击路径
4. 管理凭据-主机映射
5. 检测和规避障碍

集成现有模块：
- app.logger
- app.self_correction
- state_types.strategic
"""

from typing import Dict, List, Any, Optional
import json

# 集成现有日志模块
try:
    from app.logger import get_logger
except ImportError:
    from logger import get_logger

# 集成错误纠正模块
try:
    from app.self_correction import self_correction_manager, ErrorType, ErrorSeverity
except ImportError:
    self_correction_manager = None
    ErrorType = None
    ErrorSeverity = None

# 导入战略上下文类型
try:
    from app.state_types.strategic import (
        StrategicContext,
        get_default_strategic_context,
        update_strategic_position,
        update_attack_progress,
        ATTACK_PHASES
    )
except ImportError:
    # 降级定义
    StrategicContext = dict
    ATTACK_PHASES = {
        "internal": ["立足点", "侦察", "横向移动", "权限提升", "FLAG"]
    }

    def get_default_strategic_context() -> Dict:
        return {
            "position_type": "internal",
            "position_detail": "",
            "primary_goal": "获取FLAG",
            "attack_chain": ATTACK_PHASES["internal"],
            "current_step": 1,
            "total_steps": len(ATTACK_PHASES["internal"]),
            "credential_access": [],
            "blockers": [],
            "alternate_routes": [],
        }

    def update_strategic_position(context: Dict, position_type: str, position_detail: str) -> Dict:
        context["position_type"] = position_type
        context["position_detail"] = position_detail
        return context

    def update_attack_progress(context: Dict, current_step: int, blockers: List[str] = None, alternate_routes: List[str] = None) -> Dict:
        context["current_step"] = current_step
        if blockers:
            context["blockers"] = blockers
        if alternate_routes:
            context["alternate_routes"] = alternate_routes
        return context

# 导入attack_graph模块
try:
    from .attack_graph import AttackGraph, AttackNode, AttackEdge, build_attack_graph_from_state
    ATTACK_GRAPH_AVAILABLE = True
except ImportError:
    ATTACK_GRAPH_AVAILABLE = False
    AttackGraph = None

logger = get_logger("StrategicPlanner")


class AttackPriority:
    """攻击目标优先级"""
    CRITICAL = 5  # 域控、核心数据库
    HIGH = 4      # 文件服务器、应用服务器
    MEDIUM = 3    # 工作站、普通服务器
    LOW = 2       # 网络设备
    UNKNOWN = 1   # 未识别资产


class StrategicPlanner:
    """
    战略规划器

    AI驱动的内网渗透战略决策引擎
    """

    def __init__(self):
        self.attack_history: List[Dict] = []
        self.active_targets: List[Dict] = []

    def analyze_situation(self, state: Dict) -> StrategicContext:
        """
        分析当前攻击态势

        Returns:
            StrategicContext 结构的战略上下文
        """
        # 收集关键信息
        internal_hosts = state.get("internal_hosts") or []
        credentials = state.get("credentials") or []
        active_sessions = state.get("active_sessions") or []
        found_flags = state.get("found_flags") or []
        compromised_hosts = state.get("compromised_hosts") or []

        # 确定当前阶段
        phase = self._determine_phase(state)

        # 构建战略上下文
        context = get_default_strategic_context()
        context["position_type"] = "internal"
        context["position_detail"] = f"hosts={len(internal_hosts)}, creds={len(credentials)}, sessions={len(active_sessions)}"
        context["attack_chain"] = ATTACK_PHASES.get("internal", [])
        context["current_step"] = phase["step"]
        context["total_steps"] = len(ATTACK_PHASES.get("internal", []))

        # 资源映射
        context["credential_access"] = self._map_credential_access(credentials)

        # 障碍分析
        context["blockers"] = self._identify_blockers(state)

        # 备选路径
        context["alternate_routes"] = self._generate_alternate_routes(state)

        return context

    def _determine_phase(self, state: Dict) -> Dict:
        """确定当前攻击阶段"""
        sessions = state.get("active_sessions") or []
        hosts = state.get("internal_hosts") or []
        creds = state.get("credentials") or []
        flags = state.get("found_flags") or []

        if not sessions:
            return {"phase": "initial_access", "step": 1}
        elif len(hosts) < 2:
            return {"phase": "reconnaissance", "step": 2}
        elif len(creds) < 1:
            return {"phase": "credential_gathering", "step": 2}
        elif not any(s.get("is_admin") for s in sessions):
            return {"phase": "privilege_escalation", "step": 4}
        elif len(flags) == 0:
            return {"phase": "flag_search", "step": 5}
        else:
            return {"phase": "lateral_movement", "step": 3}

    def _map_credential_access(self, credentials: List[Dict]) -> List[Dict]:
        """映射凭据访问范围"""
        mapped = []
        for cred in credentials:
            mapped.append({
                "username": cred.get("username", ""),
                "type": cred.get("cred_type", "plaintext"),
                "scope": cred.get("host", "unknown"),
                "privilege": cred.get("privilege", "user"),
                "domain": cred.get("domain", "")
            })
        return mapped

    def _identify_blockers(self, state: Dict) -> List[str]:
        """识别当前障碍"""
        blockers = []

        if not state.get("proxy_info"):
            blockers.append("无SOCKS5代理")

        if state.get("tunnel_status") != "configured":
            blockers.append("隧道未建立")

        sessions = state.get("active_sessions") or []
        if not sessions:
            blockers.append("无活跃会话")
        elif not any(s.get("is_admin") for s in sessions):
            blockers.append("权限不足")

        creds = state.get("credentials") or []
        if len(creds) < 2:
            blockers.append("凭据数量有限")

        return blockers

    def _generate_alternate_routes(self, state: Dict) -> List[str]:
        """生成备选攻击路径"""
        routes = []

        hosts = state.get("internal_hosts") or []
        sessions = state.get("active_sessions") or []
        creds = state.get("credentials") or []

        # 检查可横向移动的目标
        compromised = set(s.get("host") for s in sessions)
        unexplored = [h for h in hosts if isinstance(h, dict) and h.get("ip") not in compromised]

        if unexplored:
            routes.append(f"横向移动到 {len(unexplored)} 台未攻陷主机")

        # 检查提权机会
        if sessions and not any(s.get("is_admin") for s in sessions):
            routes.append("尝试权限提升")

        # 检查凭据复用
        if creds:
            routes.append("尝试凭据复用攻击")

        return routes

    def prioritize_targets(self, hosts: List[Dict], credentials: List[Dict]) -> List[Dict]:
        """
        对目标主机进行优先级排序

        Args:
            hosts: 主机列表
            credentials: 凭据列表

        Returns:
            排序后的目标列表，包含优先级和建议攻击方式
        """
        prioritized = []

        for host in hosts:
            if not isinstance(host, dict):
                continue

            ip = host.get("ip", "")
            ports = host.get("ports") or []
            port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

            # 计算优先级
            priority = self._calculate_priority(port_numbers)

            # 生成攻击建议
            attack_suggestions = self._suggest_attacks(host, credentials)

            prioritized.append({
                "ip": ip,
                "priority": priority,
                "priority_name": self._priority_name(priority),
                "ports": port_numbers,
                "attack_suggestions": attack_suggestions,
                "reason": self._explain_priority(port_numbers, priority)
            })

        # 按优先级降序排序
        prioritized.sort(key=lambda x: x["priority"], reverse=True)
        return prioritized

    def _calculate_priority(self, ports: List[int]) -> int:
        """计算目标优先级"""
        # 域控特征
        if any(p in ports for p in config.DOMAIN_CONTROLLER_PORTS):
            return AttackPriority.CRITICAL

        # 数据库
        if any(p in ports for p in config.DATABASE_PORTS):
            return AttackPriority.HIGH

        # 文件服务器
        if any(p in ports for p in config.FILE_SERVICE_PORTS):
            return AttackPriority.HIGH

        # Web服务器
        if any(p in ports for p in config.WEB_PORTS):
            return AttackPriority.MEDIUM

        # 远程访问
        if any(p in ports for p in config.REMOTE_ACCESS_PORTS):
            return AttackPriority.MEDIUM

        return AttackPriority.UNKNOWN

    def _priority_name(self, priority: int) -> str:
        """获取优先级名称"""
        names = {
            5: "CRITICAL",
            4: "HIGH",
            3: "MEDIUM",
            2: "LOW",
            1: "UNKNOWN"
        }
        return names.get(priority, "UNKNOWN")

    def _suggest_attacks(self, host: Dict, credentials: List[Dict]) -> List[Dict]:
        """建议攻击方式"""
        suggestions = []
        ports = [p.get("port") for p in host.get("ports", []) if isinstance(p, dict) and p.get("port")]

        # SMB攻击
        if 445 in ports:
            suggestions.append({
                "method": "smb",
                "tools": ["crackmapexec", "impacket-psexec", "impacket-wmiexec"],
                "credential_types": ["plaintext", "ntlm"],
                "description": "SMB横向移动"
            })

        # WinRM攻击
        if 5985 in ports or 5986 in ports:
            suggestions.append({
                "method": "winrm",
                "tools": ["evil-winrm", "crackmapexec"],
                "credential_types": ["plaintext", "ntlm"],
                "description": "WinRM远程管理"
            })

        # SSH攻击
        if 22 in ports:
            suggestions.append({
                "method": "ssh",
                "tools": ["ssh", "sshpass"],
                "credential_types": ["plaintext", "ssh_key"],
                "description": "SSH登录"
            })

        # RDP攻击
        if 3389 in ports:
            suggestions.append({
                "method": "rdp",
                "tools": ["xfreerdp", "rdesktop"],
                "credential_types": ["plaintext"],
                "description": "RDP远程桌面"
            })

        return suggestions

    def _explain_priority(self, ports: List[int], priority: int) -> str:
        """解释优先级判断"""
        if priority == AttackPriority.CRITICAL:
            return "域控制器或关键基础设施"
        elif priority == AttackPriority.HIGH:
            return "高价值服务器（数据库/文件服务器）"
        elif priority == AttackPriority.MEDIUM:
            return "中等价值目标（Web服务器/工作站）"
        else:
            return "未知或低价值目标"

    def plan_attack_path(self, state: Dict) -> Dict:
        """规划攻击路径（增强版）"""
        # 分析态势
        strategic_context = self.analyze_situation(state)

        # 优先级排序
        hosts = state.get("internal_hosts") or []
        creds = state.get("credentials") or []
        priority_targets = self.prioritize_targets(hosts, creds)

        # 使用攻击图获取最佳路径
        best_path = None
        if ATTACK_GRAPH_AVAILABLE and priority_targets:
            try:
                from .attack_graph import get_best_attack_path
                target_ip = priority_targets[0]["ip"] if priority_targets else None
                if target_ip:
                    path_result = get_best_attack_path(state, target_ip)
                    if path_result.get("path"):
                        best_path = path_result
            except Exception as e:
                logger.warning(f"[StrategicPlanner] 获取最佳路径失败: {e}")

        # 推荐下一步行动
        recommended = self._recommend_next_action(state, priority_targets)

        # 构建攻击图
        attack_graph = self._build_attack_graph(state, priority_targets)

        # 记录规划历史
        self.attack_history.append({
            "context": strategic_context,
            "targets": priority_targets[:3],
            "recommended": recommended,
            "best_path": best_path
        })

        return {
            "strategic_context": strategic_context,
            "priority_targets": priority_targets,
            "recommended_action": recommended,
            "attack_graph": attack_graph,
            "best_path": best_path
        }

    def _recommend_next_action(self, state: Dict, targets: List[Dict]) -> Dict:
        """推荐下一步行动"""
        sessions = state.get("active_sessions") or []
        creds = state.get("credentials") or []

        # 无会话：建立立足点
        if not sessions:
            return {
                "action": "establish_foothold",
                "reason": "无活跃会话，需要建立立足点",
                "target": targets[0]["ip"] if targets else "unknown"
            }

        # 无权限：提权
        if not any(s.get("is_admin") for s in sessions):
            return {
                "action": "privilege_escalation",
                "reason": "当前权限不足，需要提权",
                "target": sessions[0].get("host", "unknown")
            }

        # 有凭据和未攻陷目标：横向移动
        if creds and targets:
            unexplored = [t for t in targets if t["priority"] >= AttackPriority.MEDIUM]
            if unexplored:
                return {
                    "action": "lateral_movement",
                    "reason": f"发现高价值目标 {unexplored[0]['ip']}",
                    "target": unexplored[0]["ip"],
                    "suggested_method": unexplored[0]["attack_suggestions"][0] if unexplored[0]["attack_suggestions"] else None
                }

        # 默认：搜索Flag
        return {
            "action": "flag_search",
            "reason": "搜索当前主机上的Flag",
            "target": sessions[0].get("host", "unknown") if sessions else "unknown"
        }

    def _build_attack_graph(self, state: Dict, targets: List[Dict]) -> Dict:
        """构建攻击图（集成attack_graph模块）"""
        if ATTACK_GRAPH_AVAILABLE:
            try:
                # 使用attack_graph模块构建完整攻击图
                graph = build_attack_graph_from_state(state)

                # 获取已攻陷节点
                sessions = state.get("active_sessions") or []
                compromised = {s.get("host") for s in sessions if s.get("host")}

                # 获取推荐目标
                recommended = graph.get_recommended_targets(compromised)

                # 转换为简化格式返回
                nodes = []
                edges = []

                for node_id, node in graph.nodes.items():
                    nodes.append({
                        "id": node_id,
                        "type": "compromised" if node.is_compromised else "target",
                        "priority": node.value,
                        "is_admin": node.is_admin
                    })

                for edge in graph.edges:
                    edges.append({
                        "from": edge.source,
                        "to": edge.target,
                        "method": edge.edge_type.value,
                        "cost": edge.cost
                    })

                return {
                    "nodes": nodes,
                    "edges": edges,
                    "graph_available": True
                }

            except Exception as e:
                logger.warning(f"[StrategicPlanner] 攻击图构建失败: {e}")
                # 降级到简化版本
                return self._build_simple_attack_graph(state, targets)

        # attack_graph不可用，使用简化版本
        return self._build_simple_attack_graph(state, targets)

    def _build_simple_attack_graph(self, state: Dict, targets: List[Dict]) -> Dict:
        """简化版攻击图构建（降级方案）"""
        graph = {
            "nodes": [],
            "edges": []
        }

        # 添加已攻陷节点
        sessions = state.get("active_sessions") or []
        for session in sessions:
            host = session.get("host", "")
            if host:
                graph["nodes"].append({
                    "id": host,
                    "type": "compromised",
                    "is_admin": session.get("is_admin", False)
                })

        # 添加目标节点
        for target in targets[:5]:
            graph["nodes"].append({
                "id": target["ip"],
                "type": "target",
                "priority": target["priority"]
            })

            # 添加攻击边
            if sessions:
                method = target["attack_suggestions"][0]["method"] if target["attack_suggestions"] else "unknown"
                graph["edges"].append({
                    "from": sessions[0].get("host", "unknown"),
                    "to": target["ip"],
                    "method": method
                })

        graph["graph_available"] = False
        return graph

    def get_attack_summary(self) -> Dict:
        """获取攻击摘要"""
        return {
            "total_plans": len(self.attack_history),
            "active_targets": len(self.active_targets),
            "recent_plan": self.attack_history[-1] if self.attack_history else None
        }

    def clear_history(self):
        """清空历史记录"""
        self.attack_history = []
        self.active_targets = []


def strategic_planner_node(state: Dict) -> Dict:
    """
    战略规划器节点 - LangGraph节点函数

    用于集成到CTF Agent工作流中
    """
    planner = StrategicPlanner()

    # 执行规划
    plan = planner.plan_attack_path(state)

    # 记录错误（如果有）
    if self_correction_manager and not plan.get("priority_targets"):
        try:
            self_correction_manager.record_error(
                "strategic_planner",
                ErrorType.EXECUTION_ERROR if ErrorType else "execution",
                "无法识别攻击目标",
                ErrorSeverity.MEDIUM if ErrorSeverity else "medium"
            )
        except Exception as e:
            logger.warning(f"记录错误失败: {e}")

    logger.info(f"[StrategicPlanner] 规划完成: {plan['recommended_action']['action']}")

    return {
        "strategic_context": plan["strategic_context"],
        "attack_paths": [plan["attack_graph"]],  # 添加到攻击路径列表
        "topology_priority": [(t["ip"], t["priority"]) for t in plan["priority_targets"][:5]],
        "recommended_action": plan["recommended_action"]
    }


# 全局实例
_strategic_planner = None


def get_strategic_planner() -> StrategicPlanner:
    """获取战略规划器单例"""
    global _strategic_planner
    if _strategic_planner is None:
        _strategic_planner = StrategicPlanner()
    return _strategic_planner