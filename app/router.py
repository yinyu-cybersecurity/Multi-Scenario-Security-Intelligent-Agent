# router.py - 系统的"导航" [P3优化版 + 内网模式扩展]
# 作用：定义节点间的跳转逻辑，防止死循环，处理多路径汇合
# 负责人：智能体架构师

from state import CTFState
from config import config
from typing import Dict, List, Tuple
import time
from langgraph.graph import END

class RouteGuard:
    """路由守卫 - 防止死循环和异常跳转"""

    def __init__(self):
        self.path_history: List[Tuple[str, str]] = []  # 记录走过的路径 (当前节点, 下一节点)
        self.last_transition_time: float = time.time()
        self.loop_count: Dict[str, int] = {}  # 记录每个节点的访问次数

    def check_dead_loop(self, current_node: str, next_node: str) -> bool:
        """
        检测死循环

        检测模式：
        1. A -> B -> A -> B 的来回循环
        2. 同一节点连续访问超过5次（上调自3次）
        3. 10步内出现重复路径模式

        Args:
            current_node: 当前节点名
            next_node: 下一节点名

        Returns:
            True: 检测到死循环，需要干预
            False: 正常
        """
        # 记录当前跳转
        self.path_history.append((current_node, next_node))

        # 保留最近30步（上调自20）
        if len(self.path_history) > 30:
            self.path_history = self.path_history[-30:]

        # 记录节点访问次数
        self.loop_count[next_node] = self.loop_count.get(next_node, 0) + 1

        # ---------- 死循环检测规则 ----------

        # 规则1: 同一节点连续访问超过5次（上调自3次）
        if self.loop_count.get(next_node, 0) > 5:
            print(f"[RouteGuard] 节点 {next_node} 连续访问超过5次")
            return True

        # 规则2: 检测 A->B->A 来回循环
        if len(self.path_history) >= 4:
            last4 = self.path_history[-4:]
            # 模式: A->B, B->A, A->B, B->A
            if (last4[0][1] == last4[2][0] and
                    last4[1][1] == last4[3][0] and
                    last4[0][0] == last4[2][0] and
                    last4[1][0] == last4[3][0]):
                print(f"⚠️ [RouteGuard] 检测到来回循环: {last4}")
                return True

        # 规则3: 长时间没有进展（超过300秒还在同一个模式）
        current_time = time.time()
        if current_time - self.last_transition_time > 300:
            print(f"⚠️ [RouteGuard] 300秒无进展，可能卡死")
            self.last_transition_time = current_time
            return True

        # 更新最后跳转时间
        self.last_transition_time = current_time

        return False

    def reset_loop_count(self, node: str):
        """重置特定节点的循环计数"""
        self.loop_count[node] = 0

    def get_stats(self) -> Dict:
        """获取路由统计信息"""
        return {
            "path_history": self.path_history[-10:],  # 最近10步
            "loop_count": dict(self.loop_count),
            "last_transition": self.last_transition_time
        }


# 全局路由守卫实例（单例）
_route_guard = RouteGuard()


def route_mode(state: CTFState, current_node: str) -> str:
    """
    模式路由 - 根据current_mode决定下一节点

    处理流程：
        1. 从状态获取目标模式
        2. 死循环检测
        3. 异常情况处理
        4. 返回下一节点

    Args:
        state: 当前状态
        current_node: 当前节点名（用于死循环检测）

    Returns:
        目标节点名称: 'attacker'/'explorer'/'innovator'/'hitl'/END
    """
    next_node = state.get("current_mode", "exploit")

    # [核心修复] 检查当前 URL 是否已经过侦察
    current_url = state.get("current_url")
    visited_urls = state.get("visited_urls", [])

    # 如果当前 URL 没在访问列表中，且当前不是在进行探索或创新模式，强制先去侦察
    # [P3修复] innovate 模式也需要跳过这个检查，因为可能是全新思路
    if current_url and current_url not in visited_urls and next_node not in ["explore", "innovate"]:
        print(f"📡 [Route] 检测到新 URL: {current_url}，强制切换至侦察模式")
        return "recon"

    # 1. 死循环检测
    if _route_guard.check_dead_loop(current_node, next_node):
        print(f"⚠️ [Route] 检测到死循环，但在自动模式下尝试自动恢复")
        # 重置循环计数，避免日志刷屏
        _route_guard.reset_loop_count(next_node)

        # 策略修正：如果卡在探索或创新模式，强制切回攻击模式尝试突破
        if next_node in ["explore", "innovate"]:
             return "exploit"
        # 如果卡在攻击模式，保持现状或让 ModeManager 决定（通常会因为失败分增加而自然切换）
        return next_node

    # 2. [P3修复] 移除错误的 temp_rules 检查
    # temp_rules 是 innovator_node 执行后生成的，不应在进入前检查
    # 如果 innovator 执行后没有生成有效规则，会在 strategy_filter 中处理

    # 3. 安全检查：探索模式但已经探索很多轮，考虑切回
    if next_node == "explore" and state.get("exploration_rounds", 0) > config.EXPLORE_ROUNDS_FOR_INNOVATE:
        if not state.get("site_topology"):  # 没有发现新路径
            print(f"[Route] 探索多轮无发现，尝试攻击模式")
            return "exploit"

    return next_node


def route_verify(state: CTFState, current_node: str) -> str:
    """
    验证后路由 [P3优化版] - 成功则进化，失败则检查是否需要HITL

    优先级：
        1. 找到flag -> evolution（最高优先级）
        2. 失败分过高 -> hitl
        3. 正常情况 -> mode_manager

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        "evolution" / "hitl" / "mode_manager"
    """
    # 1. 最高优先级：找到flag
    if state.get("found_flag"):
        print(f"🎉 [Route] 成功找到flag，进入进化流程")
        _route_guard.reset_loop_count("verifier")  # 重置计数
        return "evolution"

    # 2. 检查是否需要HITL
    score = state.get("failure_weighted_score", 0)
    steps = state.get("execution_steps", 0)

    if score > config.HITL_FAILURE_SCORE:
        print(f"🚨 [Route] 失败分过高 ({score:.1f})，进入HITL")
        return "hitl"

    # 3. 如果步数太多但失败分不高，强制加一个失败分触发探索
    if steps > config.MAX_TOTAL_ROUNDS * 0.7 and score < config.FAILURE_SCORE_FOR_EXPLORE:
        print(f"[Route] 步数 {steps} 已较多但失败分低，强制加0.5分触发探索")
        state["failure_weighted_score"] = score + 0.5

    # 4. 正常回到mode_manager
    return "mode_manager"


def route_hitl(state: CTFState, current_node: str) -> str:
    """
    HITL后路由 - 人类介入后的处理

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        下一节点: 通常是"mode_manager"
    """
    print(f"👤 [Route] 人类介入完成，返回决策层")
    _route_guard.reset_loop_count("hitl")  # 重置HITL的循环计数
    return "mode_manager"


def route_evolution(state: CTFState, current_node: str) -> str:
    """
    进化后路由 - 进化完成直接结束

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        END
    """
    print(f"[Route] 进化完成，结束流程")
    return END


def get_routing_stats() -> Dict:
    """获取路由统计信息（用于调试）"""
    return _route_guard.get_stats()


# ==============================================================================
# 内网渗透路由扩展 (Internal Network Routing Extension)
# 添加时间：2026-03-22
# ==============================================================================

def route_internal_mode(state: CTFState, current_node: str) -> str:
    """
    内网模式路由决策

    根据内网渗透状态决定下一阶段:
    1. internal_recon: 内网侦察
    2. credential_gather: 凭据收集
    3. lateral_move: 横向移动
    4. privilege_escalation: 权限提升

    Args:
        state: 当前状态
        current_node: 当前节点名

    Returns:
        下一节点名称
    """
    # 检查是否处于内网模式
    if not state.get("internal_mode", False):
        return "mode_manager"  # 返回Web模式

    # 安全获取列表，处理None值
    internal_hosts = state.get("internal_hosts") or []
    credentials = state.get("credentials") or []
    active_sessions = state.get("active_sessions") or []
    current_target = state.get("current_internal_target", "")
    pivot_host = state.get("pivot_host", "")

    # 死循环检测
    if _route_guard.check_dead_loop(current_node, "internal_recon"):
        print(f"[InternalRoute] 检测到潜在死循环，重置计数")
        _route_guard.reset_loop_count("internal_recon")

    # 决策逻辑
    # 阶段1: 侦察 - 如果发现的主机少于5个，继续侦察
    if len(internal_hosts) < 5:
        print(f"[InternalRoute] 侦察阶段: 已发现 {len(internal_hosts)} 台主机")
        return "internal_recon"

    # 阶段2: 凭据收集 - 如果有目标但没有凭据
    if current_target and len(credentials) < 3:
        print(f"[InternalRoute] 凭据收集阶段: 目标 {current_target}, 凭据 {len(credentials)} 组")
        return "credential_gather"

    # 阶段3: 横向移动 - 如果有凭据且有新目标
    if credentials and internal_hosts:
        # 检查是否所有主机都已被攻陷
        compromised_hosts = [s.get("host") for s in active_sessions if s.get("host")]
        unexploited = [h for h in internal_hosts if h.get("ip") not in compromised_hosts]

        if unexploited:
            print(f"[InternalRoute] 横向移动阶段: {len(unexploited)} 台未攻陷主机")
            return "lateral_move"

    # 阶段4: 权限提升 - 如果有活跃会话但需要更高权限
    if active_sessions:
        # 检查是否有system/admin权限
        for session in active_sessions:
            if session.get("shell_type") in ["shell", "meterpreter"]:
                print(f"[InternalRoute] 权限提升阶段: 检查会话权限")
                return "privilege_escalation"

    # 默认返回侦察
    return "internal_recon"


def route_internal_to_web(state: CTFState) -> str:
    """
    内网到Web模式的切换判断

    当内网渗透完成或需要回到Web攻击时调用

    Args:
        state: 当前状态

    Returns:
        "internal" 或 "web"
    """
    # 如果内网模式已关闭
    if not state.get("internal_mode", False):
        return "web"

    # 如果找到了最终目标（如域控被攻陷）
    active_sessions = state.get("active_sessions", [])
    for session in active_sessions:
        if session.get("is_dc", False) and session.get("is_admin", False):
            print(f"[InternalRoute] 域控已被攻陷，完成内网渗透")
            return "web"

    # 如果步数过多，考虑回到Web模式
    steps = state.get("execution_steps", 0)
    if steps > config.MAX_TOTAL_ROUNDS * 0.8:
        print(f"[InternalRoute] 步数过多，切换回Web模式")
        return "web"

    return "internal"


def get_internal_next_target(state: CTFState) -> str:
    """
    选择下一个内网目标

    优先级:
    1. 域控制器
    2. 高价值服务器（数据库、文件服务器）
    3. 普通工作站

    Args:
        state: 当前状态

    Returns:
        目标IP
    """
    # 安全获取列表，处理None值
    internal_hosts = state.get("internal_hosts") or []
    active_sessions = state.get("active_sessions") or []
    compromised = [s.get("host") for s in active_sessions if s.get("host")]

    # 优先级排序
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if not ip or ip in compromised:
            continue

        ports = host.get("ports") or []
        port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

        # 域控制器特征
        if any(p in port_numbers for p in [88, 389, 636, 3268]):
            return ip

        # 高价值服务器
        if any(p in port_numbers for p in [1433, 3306, 5432, 445]):
            return ip

    # 返回第一个未攻陷的主机
    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if ip and ip not in compromised:
            return ip

    return ""