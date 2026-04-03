# app/state/store.py

"""
极简状态容器 - CTF Agent专用

设计原则：
1. 不需要响应式特性（订阅、监听器）
2. 不需要引用相等检查
3. 只需要简单的字典容器

CTF Agent场景特点：
- 单线程执行
- 状态更新频率低
- 不需要细粒度订阅
"""


class AgentState:
    """
    简化的状态容器

    只保留实际需要的功能：
    - get/set/update: 基本操作
    - to_dict: 导出状态
    - to_context_string: 生成上下文提示
    """

    def __init__(self):
        self._data: dict = {}

    def get(self, key: str, default=None):
        """获取状态值"""
        return self._data.get(key, default)

    def set(self, key: str, value):
        """设置状态值"""
        self._data[key] = value

    def update(self, updates: dict):
        """批量更新状态"""
        self._data.update(updates)

    def to_dict(self) -> dict:
        """导出状态字典"""
        return dict(self._data)

    def to_context_string(self) -> str:
        """
        生成上下文提示

        用于注入到LLM消息中，告诉AI当前状态
        """
        s = self._data
        parts = []
        if s.get("target"):
            parts.append(f"Target: {s['target']}")
        if s.get("findings"):
            parts.append(f"Findings: {len(s['findings'])}")
        if s.get("current_phase"):
            parts.append(f"Phase: {s['current_phase']}")

        return " | ".join(parts) if parts else ""

    def __contains__(self, key: str) -> bool:
        return key in self._data


def get_default_agent_state() -> AgentState:
    """
    获取默认Agent状态

    只设置系统运行必需的最小状态
    """
    state = AgentState()
    state.update({
        "is_executing": False,
    })
    return state


# 全局状态实例
_agent_state: AgentState = None


def get_agent_state() -> AgentState:
    """获取全局Agent状态"""
    global _agent_state
    if _agent_state is None:
        _agent_state = get_default_agent_state()
    return _agent_state


__all__ = [
    "AgentState",
    "get_default_agent_state",
    "get_agent_state",
]