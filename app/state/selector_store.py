# Selector Store - 状态订阅系统
#
# 借鉴Claude Code的Selector模式
# 实现精确状态分片订阅，减少无效更新

from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
import asyncio
from copy import deepcopy

# 导入状态类型
from app.state.state_v3 import CTFStateV3, get_state_slice_for_agent
from app.agents.base import AgentType


@dataclass
class Subscription:
    """订阅记录"""
    subscriber_id: str
    agent_type: AgentType
    topics: List[str]
    callback: Optional[Callable] = None
    last_snapshot: Dict[str, Any] = field(default_factory=dict)


class SelectorStore:
    """
    Selector状态订阅系统

    借鉴Claude Code的useAppState(selector)设计:
    - Agent只订阅需要的状态切片
    - 状态变化时只通知相关订阅者
    - 减少上下文传输开销

    核心机制:
    1. register_subscription - Agent注册订阅
    2. update_state - 更新状态并通知订阅者
    3. get_subscribed_state - 获取订阅的状态切片
    4. detect_changes - 检测状态变化
    """

    def __init__(self):
        self._state: Optional[CTFStateV3] = None
        self._subscriptions: Dict[str, Subscription] = {}
        self._change_log: List[Dict] = []
        self._lock = asyncio.Lock()

    async def initialize(self, initial_state: CTFStateV3):
        """初始化状态"""
        async with self._lock:
            self._state = deepcopy(initial_state)

    async def register_subscription(
        self,
        subscriber_id: str,
        agent_type: AgentType,
        custom_topics: List[str] = None,
        callback: Callable = None
    ) -> Subscription:
        """
        注册订阅

        Args:
            subscriber_id: 订阅者ID（通常是Agent session_id）
            agent_type: Agent类型
            custom_topics: 自定义订阅主题（可选）
            callback: 状态变化回调函数

        Returns:
            Subscription订阅记录
        """
        async with self._lock:
            # 确定订阅主题
            if custom_topics:
                topics = custom_topics
            else:
                topics = get_state_slice_for_agent(agent_type)

            subscription = Subscription(
                subscriber_id=subscriber_id,
                agent_type=agent_type,
                topics=topics,
                callback=callback,
                last_snapshot={}
            )

            self._subscriptions[subscriber_id] = subscription

            # 初始化快照
            if self._state:
                subscription.last_snapshot = await self._extract_slice(
                    self._state, topics
                )

            return subscription

    async def unregister_subscription(self, subscriber_id: str):
        """取消订阅"""
        async with self._lock:
            self._subscriptions.pop(subscriber_id, None)

    async def update_state(
        self,
        updates: Dict[str, Any],
        notify: bool = True
    ) -> Dict[str, Any]:
        """
        更新状态

        Args:
            updates: 状态更新字典
            notify: 是否通知订阅者

        Returns:
            变化的主题列表
        """
        async with self._lock:
            if not self._state:
                return {}

            # 应用更新
            changes = {}
            for key, value in updates.items():
                if key in self._state:
                    old_value = self._state.get(key)

                    # 检测变化
                    if self._value_changed(old_value, value):
                        self._state[key] = value
                        changes[key] = {
                            "old": old_value,
                            "new": value
                        }

                        # 记录变化日志
                        self._change_log.append({
                            "key": key,
                            "timestamp": self._get_timestamp(),
                            "change_type": "update"
                        })

            # 通知订阅者
            if notify and changes:
                await self._notify_subscribers(changes)

            return changes

    async def get_subscribed_state(
        self,
        subscriber_id: str
    ) -> Dict[str, Any]:
        """
        获取订阅的状态切片

        Args:
            subscriber_id: 订阅者ID

        Returns:
            订阅的状态切片
        """
        async with self._lock:
            subscription = self._subscriptions.get(subscriber_id)
            if not subscription or not self._state:
                return {}

            return await self._extract_slice(
                self._state,
                subscription.topics
            )

    async def get_full_state(self) -> Optional[CTFStateV3]:
        """获取完整状态（Coordinator用）"""
        async with self._lock:
            return deepcopy(self._state) if self._state else None

    async def detect_changes_for_subscriber(
        self,
        subscriber_id: str
    ) -> Dict[str, Any]:
        """
        检测订阅者的状态变化

        用于判断是否需要重新渲染/处理

        Args:
            subscriber_id: 订阅者ID

        Returns:
            变化的主题和差异
        """
        async with self._lock:
            subscription = self._subscriptions.get(subscriber_id)
            if not subscription or not self._state:
                return {}

            # 获取当前切片
            current_slice = await self._extract_slice(
                self._state,
                subscription.topics
            )

            # 与上次快照对比
            changes = {}
            for topic in subscription.topics:
                old_val = subscription.last_snapshot.get(topic)
                new_val = current_slice.get(topic)

                if self._value_changed(old_val, new_val):
                    changes[topic] = {
                        "old": old_val,
                        "new": new_val
                    }

            # 更新快照
            subscription.last_snapshot = current_slice

            return changes

    async def batch_update(
        self,
        updates_list: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        批量更新状态

        用于多个Agent并行更新后的合并

        Args:
            updates_list: 多个更新字典列表

        Returns:
            合并后的变化
        """
        async with self._lock:
            all_changes = {}

            for updates in updates_list:
                for key, value in updates.items():
                    if key in self._state:
                        old_value = self._state.get(key)

                        if self._value_changed(old_value, value):
                            self._state[key] = value
                            all_changes[key] = {
                                "old": old_value,
                                "new": value
                            }

            if all_changes:
                await self._notify_subscribers(all_changes)

            return all_changes

    async def fork_state_for_subagent(
        self,
        parent_subscriber_id: str,
        child_subscriber_id: str,
        child_agent_type: AgentType,
        inherit_topics: List[str] = None
    ) -> Dict[str, Any]:
        """
        Fork状态给子Agent

        借鉴Claude Code的Fork子Agent机制
        子Agent继承父Agent的订阅状态

        Args:
            parent_subscriber_id: 父Agent订阅ID
            child_subscriber_id: 子Agent订阅ID
            child_agent_type: 子Agent类型
            inherit_topics: 继承的主题（可选）

        Returns:
            Fork的状态切片
        """
        async with self._lock:
            parent_subscription = self._subscriptions.get(parent_subscriber_id)

            # 确定子Agent主题
            child_topics = inherit_topics or get_state_slice_for_agent(child_agent_type)

            # 如果父Agent有额外主题，合并
            if parent_subscription and "*" in parent_subscription.topics:
                # 父Agent订阅全量，子Agent继承自己的切片
                pass
            elif parent_subscription:
                # 合并父Agent的主题
                child_topics = list(set(child_topics + parent_subscription.topics))

            # 注册子Agent订阅
            child_subscription = await self.register_subscription(
                subscriber_id=child_subscriber_id,
                agent_type=child_agent_type,
                custom_topics=child_topics
            )

            # 返回Fork的状态切片
            return child_subscription.last_snapshot

    async def _extract_slice(
        self,
        state: CTFStateV3,
        topics: List[str]
    ) -> Dict[str, Any]:
        """提取状态切片"""
        slice_data = {}

        if "*" in topics:
            # 全量订阅
            return deepcopy(dict(state))

        for topic in topics:
            if topic in state:
                slice_data[topic] = deepcopy(state[topic])

        return slice_data

    def _value_changed(self, old_value: Any, new_value: Any) -> bool:
        """检测值变化"""
        if old_value is None and new_value is None:
            return False

        if old_value is None or new_value is None:
            return True

        # 简单比较
        if isinstance(old_value, (list, dict)):
            return old_value != new_value

        return old_value != new_value

    async def _notify_subscribers(self, changes: Dict[str, Any]):
        """通知订阅者"""
        for subscriber_id, subscription in self._subscriptions.items():
            # 检查订阅者是否关心变化
            relevant_changes = {}

            if "*" in subscription.topics:
                relevant_changes = changes
            else:
                for changed_topic in changes:
                    if changed_topic in subscription.topics:
                        relevant_changes[changed_topic] = changes[changed_topic]

            if relevant_changes and subscription.callback:
                try:
                    # 调用回调
                    if asyncio.iscoroutinefunction(subscription.callback):
                        await subscription.callback(
                            subscriber_id,
                            relevant_changes
                        )
                    else:
                        subscription.callback(subscriber_id, relevant_changes)
                except Exception as e:
                    print(f"[SelectorStore] Callback error: {e}")

    def _get_timestamp(self) -> float:
        """获取时间戳"""
        import time
        return time.time()

    def get_subscription_stats(self) -> Dict:
        """获取订阅统计"""
        return {
            "total_subscriptions": len(self._subscriptions),
            "by_agent_type": {
                agent.value: sum(
                    1 for s in self._subscriptions.values()
                    if s.agent_type == agent
                )
                for agent in AgentType
            },
            "change_log_size": len(self._change_log),
        }


# ============================================
# 便捷函数
# ============================================

_selector_store: Optional[SelectorStore] = None


def get_selector_store() -> SelectorStore:
    """获取SelectorStore单例"""
    global _selector_store
    if _selector_store is None:
        _selector_store = SelectorStore()
    return _selector_store


async def subscribe_state(
    subscriber_id: str,
    agent_type: AgentType,
    callback: Callable = None
) -> Dict[str, Any]:
    """便捷函数：订阅状态"""
    store = get_selector_store()
    subscription = await store.register_subscription(
        subscriber_id=subscriber_id,
        agent_type=agent_type,
        callback=callback
    )
    return subscription.last_snapshot


async def update_state_slice(updates: Dict[str, Any]) -> Dict[str, Any]:
    """便捷函数：更新状态切片"""
    store = get_selector_store()
    return await store.update_state(updates)