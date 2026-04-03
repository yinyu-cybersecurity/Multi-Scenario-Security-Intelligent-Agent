"""
Claude Code AppStateStore - Python移植版

完全复制Claude Code的AppStateStore.ts设计:
- 外部Store模式
- 单向数据流
- 细粒度订阅
- 引用相等检查
"""

from typing import TypeVar, Generic, Callable, Set, Optional, Dict, Any
from dataclasses import dataclass, field
from copy import deepcopy
import threading

T = TypeVar('T')
Listener = Callable[[], None]
OnChange = Callable[[T, T], None]


@dataclass
class Store(Generic[T]):
    """
    通用Store - 框架无关的状态管理

    完全复制Claude Code的store.ts设计
    """
    _state: T
    _listeners: Set[Listener] = field(default_factory=set)
    _on_change: Optional[OnChange] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def get_state(self) -> T:
        """获取当前状态"""
        with self._lock:
            return self._state

    def set_state(self, updater: Callable[[T], T]) -> None:
        """
        更新状态

        关键设计:
        - 引用相等检查 (Object.is)
        - 如果返回相同引用，跳过更新
        """
        with self._lock:
            prev = self._state
            next_state = updater(prev)

            # 引用相等检查 - Claude Code核心优化
            if next_state is prev:
                return

            self._state = next_state

            # 触发onChange回调
            if self._on_change:
                self._on_change(next_state, prev)

        # 通知所有监听器（在锁外执行，避免死锁）
        for listener in list(self._listeners):
            listener()

    def subscribe(self, listener: Listener) -> Callable[[], None]:
        """
        订阅状态变化

        返回取消订阅函数
        """
        self._listeners.add(listener)
        return lambda: self._listeners.discard(listener)


def create_store(
    initial_state: T,
    on_change: OnChange = None,
) -> Store[T]:
    """创建Store实例"""
    return Store(_state=initial_state, _on_change=on_change)


class AppState:
    """
    应用状态 - 动态字典

    关键设计:
    - 无预置TypedDict字段
    - AI可以随时创建新字段
    - 动态状态，完全灵活
    """

    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def update(self, updates: Dict[str, Any]) -> None:
        with self._lock:
            self._data.update(updates)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._data)

    def __contains__(self, key: str) -> bool:
        return key in self._data


def get_default_app_state() -> AppState:
    """
    获取默认应用状态

    遵循Claude Code模式:
    - 无预置业务字段
    - 只设置系统运行必需的最小状态
    - AI可以动态创建任何字段
    """
    state = AppState()
    # 只设置真正必需的系统字段
    state.update({
        "is_executing": False,  # 执行状态标志
    })
    return state


# 全局Store实例
_app_state_store: Optional[Store[AppState]] = None
_store_lock = threading.Lock()


def get_app_state_store() -> Store[AppState]:
    """获取全局AppState Store"""
    global _app_state_store
    with _store_lock:
        if _app_state_store is None:
            _app_state_store = create_store(get_default_app_state())
        return _app_state_store


__all__ = [
    "Store",
    "create_store",
    "AppState",
    "get_default_app_state",
    "get_app_state_store",
]