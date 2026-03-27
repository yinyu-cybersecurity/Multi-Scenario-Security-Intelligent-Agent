# app/node_control.py
"""
节点控制模块 - 管理节点启用/禁用状态

功能:
- 运行时动态控制节点是否执行
- 被禁用的节点直接跳过，不消耗资源
- 支持内存优化：禁用不需要的模块可以降低内存占用

使用方式:
    from node_control import node_control, skip_if_disabled

    # 检查节点是否启用
    if node_control.is_enabled("internal_recon"):
        ...

    # 使用装饰器包装节点
    @skip_if_disabled
    def my_node(state):
        ...
"""

from typing import Dict, Any, Callable, Optional
from functools import wraps
import threading


class NodeControl:
    """
    节点控制管理器

    线程安全的单例模式，管理所有节点的启用状态
    """

    # 默认所有节点启用
    DEFAULT_NODES = [
        # 核心节点 - 始终启用
        "challenge_type_detector", "recon", "analyst", "strategy_filter",
        "mode_manager", "attacker", "verifier", "explorer", "innovator", "evolution",
        # 内网渗透节点
        "internal_recon", "lateral_move", "privilege_escalation",
        "persistence", "credential_gather", "flag_search",
        "post_exploit", "upload_tools", "setup_tunnel",
        # 其他类型节点
        "crypto_analyst", "crypto_solver",
        "pwn_analyst", "pwn_exploiter",
        "reverse_analyst", "reverse_decompiler",
        "misc_analyst", "misc_extractor",
    ]

    # 节点分组 - 用于批量禁用
    NODE_GROUPS = {
        "core": ["challenge_type_detector", "recon", "analyst", "strategy_filter",
                 "mode_manager", "attacker", "verifier", "explorer", "innovator", "evolution"],
        "internal": ["internal_recon", "lateral_move", "privilege_escalation",
                     "persistence", "credential_gather", "flag_search",
                     "post_exploit", "upload_tools", "setup_tunnel"],
        "crypto": ["crypto_analyst", "crypto_solver"],
        "pwn": ["pwn_analyst", "pwn_exploiter"],
        "reverse": ["reverse_analyst", "reverse_decompiler"],
        "misc": ["misc_analyst", "misc_extractor"],
    }

    # 节点内存占用估算 (MB) - 用于显示禁用后的内存节省
    NODE_MEMORY_ESTIMATE = {
        "internal_recon": 50,
        "lateral_move": 30,
        "privilege_escalation": 20,
        "credential_gather": 40,
        "flag_search": 10,
        "persistence": 20,
        "post_exploit": 15,
        "upload_tools": 10,
        "setup_tunnel": 10,
        "crypto_analyst": 30,
        "crypto_solver": 25,
        "pwn_analyst": 35,
        "pwn_exploiter": 40,
        "reverse_analyst": 30,
        "reverse_decompiler": 35,
        "misc_analyst": 20,
        "misc_extractor": 25,
    }

    def __init__(self):
        self._enabled: Dict[str, bool] = {name: True for name in self.DEFAULT_NODES}
        self._lock = threading.RLock()

    def is_enabled(self, node_name: str) -> bool:
        """检查节点是否启用"""
        with self._lock:
            return self._enabled.get(node_name, True)

    def set_enabled(self, node_name: str, enabled: bool) -> bool:
        """
        设置节点启用状态

        Args:
            node_name: 节点名称
            enabled: 是否启用

        Returns:
            是否设置成功
        """
        with self._lock:
            if node_name in self._enabled:
                self._enabled[node_name] = enabled
                return True
            return False

    def toggle(self, node_name: str) -> bool:
        """切换节点启用状态"""
        with self._lock:
            if node_name in self._enabled:
                self._enabled[node_name] = not self._enabled[node_name]
                return self._enabled[node_name]
            return False

    def get_all_status(self) -> Dict[str, bool]:
        """获取所有节点状态"""
        with self._lock:
            return self._enabled.copy()

    def disable_group(self, group_name: str) -> int:
        """
        禁用一组节点

        Returns:
            禁用的节点数量
        """
        nodes = self.NODE_GROUPS.get(group_name, [])
        count = 0
        with self._lock:
            for node in nodes:
                if node in self._enabled:
                    self._enabled[node] = False
                    count += 1
        return count

    def enable_group(self, group_name: str) -> int:
        """
        启用一组节点

        Returns:
            启用的节点数量
        """
        nodes = self.NODE_GROUPS.get(group_name, [])
        count = 0
        with self._lock:
            for node in nodes:
                if node in self._enabled:
                    self._enabled[node] = True
                    count += 1
        return count

    def get_memory_savings(self) -> int:
        """
        计算当前禁用节点节省的内存 (MB)

        Returns:
            节省的内存 MB 数
        """
        total = 0
        with self._lock:
            for node, enabled in self._enabled.items():
                if not enabled:
                    total += self.NODE_MEMORY_ESTIMATE.get(node, 0)
        return total

    def get_disabled_nodes(self) -> list:
        """获取所有被禁用的节点列表"""
        with self._lock:
            return [name for name, enabled in self._enabled.items() if not enabled]

    def get_node_info(self, node_name: str) -> Dict[str, Any]:
        """获取节点详细信息"""
        return {
            "name": node_name,
            "enabled": self.is_enabled(node_name),
            "memory_estimate": self.NODE_MEMORY_ESTIMATE.get(node_name, 0),
            "group": self._get_node_group(node_name),
        }

    def _get_node_group(self, node_name: str) -> str:
        """获取节点所属分组"""
        for group, nodes in self.NODE_GROUPS.items():
            if node_name in nodes:
                return group
        return "unknown"


# 全局单例
node_control = NodeControl()


def skip_if_disabled(node_func: Callable) -> Callable:
    """
    装饰器：如果节点被禁用，直接返回空结果

    用法:
        @skip_if_disabled
        def internal_recon_node(state: CTFState) -> Dict:
            # 节点逻辑
            ...

    被禁用的节点会:
    1. 记录一条日志
    2. 直接返回传入的 state（不做任何修改）
    3. 不执行任何实际逻辑
    """
    @wraps(node_func)
    def wrapper(state: Dict[str, Any]) -> Dict[str, Any]:
        node_name = node_func.__name__.replace("_node", "")

        # 检查节点是否被禁用
        if not node_control.is_enabled(node_name):
            # 导入日志函数（延迟导入避免循环依赖）
            try:
                from logger import node_log
                node_log(node_name, f"节点已禁用，跳过执行", "info")
            except:
                print(f"[{node_name}] 节点已禁用，跳过执行")

            # 返回空修改，不执行实际逻辑
            return {
                "node_messages": [{
                    "node": node_name,
                    "status": "disabled",
                    "message": "节点已被禁用"
                }]
            }

        # 节点启用，执行实际逻辑
        return node_func(state)

    return wrapper


def create_disabled_wrapper(node_name: str, node_func: Callable) -> Callable:
    """
    创建禁用检查包装器（用于无法使用装饰器的场景）

    集成性能监控，自动跟踪节点执行时间

    Args:
        node_name: 节点名称
        node_func: 原始节点函数

    Returns:
        包装后的函数
    """
    @wraps(node_func)
    def wrapper(state: Dict[str, Any]) -> Dict[str, Any]:
        if not node_control.is_enabled(node_name):
            try:
                from logger import node_log
                node_log(node_name, f"节点已禁用，跳过执行", "info")
            except:
                print(f"[{node_name}] 节点已禁用，跳过执行")

            return {
                "node_messages": [{
                    "node": node_name,
                    "status": "disabled",
                    "message": "节点已被禁用"
                }]
            }

        # 使用性能监控跟踪节点执行
        try:
            from performance import performance_monitor
            with performance_monitor.track_node(node_name):
                return node_func(state)
        except ImportError:
            # 性能监控不可用时直接执行
            return node_func(state)

    return wrapper


# 便捷函数
def is_node_enabled(node_name: str) -> bool:
    """检查节点是否启用"""
    return node_control.is_enabled(node_name)


def toggle_node(node_name: str, enabled: Optional[bool] = None) -> bool:
    """
    切换或设置节点状态

    Args:
        node_name: 节点名称
        enabled: None表示切换，True/False表示设置

    Returns:
        新的启用状态
    """
    if enabled is None:
        return node_control.toggle(node_name)
    else:
        node_control.set_enabled(node_name, enabled)
        return enabled