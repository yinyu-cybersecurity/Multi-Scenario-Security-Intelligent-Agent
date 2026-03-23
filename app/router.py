# router.py - 系统的"导航" [优化版 + 内网模式扩展]
# 作用：定义节点间的跳转逻辑，防止死循环，处理多路径汇合

from state import CTFState
from config import config
from typing import Dict, List, Tuple
import time
from langgraph.graph import END


class RouteGuard:
    """路由守卫 - 防止死循环和异常跳转"""

    def __init__(self):
        self.path_history: List[Tuple[str, str]] = []
        self.last_transition_time: float = time.time()
        self.loop_count: Dict[str, int] = {}

    def check_dead_loop(self, current_node: str, next_node: str) -> bool:
        """检测死循环"""
        self.path_history.append((current_node, next_node))
        if len(self.path_history) > 50:
            self.path_history = self.path_history[-50:]

        self.loop_count[next_node] = self.loop_count.get(next_node, 0) + 1

        # 同一节点连续访问超过10次
        if self.loop_count.get(next_node, 0) > 10:
            print(f"[RouteGuard] 节点 {next_node} 连续访问超过10次")
            return True

        # A->B->A 来回循环
        if len(self.path_history) >= 4:
            last4 = self.path_history[-4:]
            if (last4[0][1] == last4[2][0] and
                    last4[1][1] == last4[3][0] and
                    last4[0][0] == last4[2][0] and
                    last4[1][0] == last4[3][0]):
                return True

        self.last_transition_time = time.time()
        return False

    def reset_loop_count(self, node: str):
        self.loop_count[node] = 0

    def reset_all(self):
        """重置所有计数，用于新任务"""
        self.path_history = []
        self.loop_count = {}
        self.last_transition_time = time.time()


_route_guard = RouteGuard()


def route_mode(state: CTFState, current_node: str) -> str:
    """模式路由 - 根据current_mode决定下一节点"""
    next_node = state.get("current_mode", "exploit")
    current_url = state.get("current_url")
    visited_urls = state.get("visited_urls", [])

    # 新URL需要先侦察
    if current_url and current_url not in visited_urls and next_node not in ["explore", "innovate"]:
        print(f"📡 [Route] 检测到新 URL: {current_url}，强制切换至侦察模式")
        return "recon"

    if _route_guard.check_dead_loop(current_node, next_node):
        _route_guard.reset_loop_count(next_node)
        if next_node in ["explore", "innovate"]:
            return "exploit"
        return next_node

    if next_node == "explore" and state.get("exploration_rounds", 0) > config.EXPLORE_ROUNDS_FOR_INNOVATE:
        if not state.get("site_topology"):
            return "exploit"

    return next_node


def route_verify(state: CTFState, current_node: str) -> str:
    """验证后路由 - 成功则进化，失败回到mode_manager"""
    if state.get("found_flag"):
        print(f"🎉 [Route] 成功找到flag，进入进化流程")
        _route_guard.reset_loop_count("verifier")
        return "evolution"

    # 正常回到mode_manager
    return "mode_manager"


def route_evolution(state: CTFState, current_node: str) -> str:
    """进化后路由 - 进化完成直接结束"""
    print(f"[Route] 进化完成，结束流程")
    return END


def get_routing_stats() -> Dict:
    return _route_guard.get_stats()


def reset_routing():
    """重置路由状态，用于新任务"""
    _route_guard.reset_all()


# ==============================================================================
# 内网渗透路由扩展
# ==============================================================================

def route_internal_mode(state: CTFState, current_node: str) -> str:
    """内网模式路由决策"""
    if not state.get("internal_mode", False):
        return "mode_manager"

    internal_hosts = state.get("internal_hosts") or []
    credentials = state.get("credentials") or []
    active_sessions = state.get("active_sessions") or []
    current_target = state.get("current_internal_target", "")

    if _route_guard.check_dead_loop(current_node, "internal_recon"):
        _route_guard.reset_loop_count("internal_recon")

    if len(internal_hosts) < 5:
        return "internal_recon"

    if current_target and len(credentials) < 3:
        return "credential_gather"

    if credentials and internal_hosts:
        compromised_hosts = [s.get("host") for s in active_sessions if s.get("host")]
        unexploited = [h for h in internal_hosts if h.get("ip") not in compromised_hosts]
        if unexploited:
            return "lateral_move"

    if active_sessions:
        for session in active_sessions:
            if session.get("shell_type") in ["shell", "meterpreter"]:
                return "privilege_escalation"

    return "internal_recon"


def route_internal_to_web(state: CTFState) -> str:
    """内网到Web模式的切换判断"""
    if not state.get("internal_mode", False):
        return "web"

    active_sessions = state.get("active_sessions", [])
    for session in active_sessions:
        if session.get("is_dc", False) and session.get("is_admin", False):
            return "web"

    steps = state.get("execution_steps", 0)
    if steps > config.MAX_TOTAL_ROUNDS * 0.8:
        return "web"

    return "internal"


def get_internal_next_target(state: CTFState) -> str:
    """选择下一个内网目标"""
    internal_hosts = state.get("internal_hosts") or []
    active_sessions = state.get("active_sessions") or []
    compromised = [s.get("host") for s in active_sessions if s.get("host")]

    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if not ip or ip in compromised:
            continue
        ports = host.get("ports") or []
        port_numbers = [p.get("port") for p in ports if isinstance(p, dict) and p.get("port")]

        if any(p in port_numbers for p in [88, 389, 636, 3268]):
            return ip
        if any(p in port_numbers for p in [1433, 3306, 5432, 445]):
            return ip

    for host in internal_hosts:
        if not isinstance(host, dict):
            continue
        ip = host.get("ip", "")
        if ip and ip not in compromised:
            return ip

    return ""