"""
Selector Store - Claude Code External Store模式

提供细粒度的选择器订阅，避免不必要的重渲染。
完全复制Claude Code的selector设计模式。
"""

from typing import TypeVar, Generic, Callable, Optional, Dict, Any, Set
from dataclasses import dataclass, field
import threading

from app.state.store import AppState, get_app_state_store


T = TypeVar('T')
Selector = Callable[[AppState], T]
Listener = Callable[[], None]


@dataclass
class SelectorSubscription(Generic[T]):
    """选择器订阅"""
    selector: Selector[T]
    listener: Listener
    last_value: T = field(default=None)


class SelectorStore:
    """
    选择器Store - 细粒度订阅

    完全复制Claude Code的selector模式:
    - 只在选择的值变化时触发
    - 避免不必要的状态更新
    - 引用相等检查
    """

    def __init__(self):
        self._store = get_app_state_store()
        self._subscriptions: Dict[str, SelectorSubscription] = {}
        self._lock = threading.Lock()
        self._unsubscribe_store: Optional[Callable[[], None]] = None

        # 订阅底层Store的变化
        self._unsubscribe_store = self._store.subscribe(self._on_store_change)

    def _on_store_change(self) -> None:
        """Store变化时检查所有选择器"""
        state = self._store.get_state()

        with self._lock:
            for key, sub in list(self._subscriptions.items()):
                try:
                    new_value = sub.selector(state)

                    # 引用相等检查
                    if new_value is not sub.last_value:
                        sub.last_value = new_value
                        sub.listener()
                except Exception:
                    pass  # 忽略选择器错误

    def subscribe_selector(
        self,
        key: str,
        selector: Selector[T],
        listener: Listener
    ) -> Callable[[], None]:
        """
        订阅选择器

        Args:
            key: 订阅键
            selector: 选择器函数
            listener: 监听器函数

        Returns:
            取消订阅函数
        """
        with self._lock:
            # 获取初始值
            state = self._store.get_state()
            initial_value = selector(state)

            self._subscriptions[key] = SelectorSubscription(
                selector=selector,
                listener=listener,
                last_value=initial_value
            )

        return lambda: self._unsubscribe_selector(key)

    def _unsubscribe_selector(self, key: str) -> None:
        """取消选择器订阅"""
        with self._lock:
            self._subscriptions.pop(key, None)

    def get_selector_value(self, selector: Selector[T]) -> T:
        """获取选择器当前值"""
        state = self._store.get_state()
        return selector(state)

    def update_state(self, updater: Callable[[AppState], AppState]) -> None:
        """更新底层状态"""
        self._store.set_state(updater)

    def get_state(self) -> AppState:
        """获取当前状态"""
        return self._store.get_state()


# 全局实例
_selector_store: Optional[SelectorStore] = None
_store_lock = threading.Lock()


def get_selector_store() -> SelectorStore:
    """获取全局SelectorStore"""
    global _selector_store
    with _store_lock:
        if _selector_store is None:
            _selector_store = SelectorStore()
        return _selector_store


__all__ = [
    "SelectorStore",
    "get_selector_store",
]