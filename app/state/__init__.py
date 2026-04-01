# State系统
#
# 借鉴Claude Code的状态管理设计

from .state_v3 import (
    CTFStateV3,
    ChallengeType,
    PhaseType,
    Priority,
    ToolResult,
    AgentSession,
    ChallengeInfo,
    AttackPlan,
    Finding,
    FlagSubmission,
    StateSlice,
    get_state_slice_for_agent,
    create_initial_state,
    reduce_messages_for_cache,
)

from .selector_store import (
    SelectorStore,
    Subscription,
    get_selector_store,
    subscribe_state,
    update_state_slice,
)

__all__ = [
    # 状态类型
    "CTFStateV3",
    "ChallengeType",
    "PhaseType",
    "Priority",
    "ToolResult",
    "AgentSession",
    "ChallengeInfo",
    "AttackPlan",
    "Finding",
    "FlagSubmission",

    # 状态切片
    "StateSlice",
    "get_state_slice_for_agent",
    "create_initial_state",
    "reduce_messages_for_cache",

    # Selector系统
    "SelectorStore",
    "Subscription",
    "get_selector_store",
    "subscribe_state",
    "update_state_slice",
]