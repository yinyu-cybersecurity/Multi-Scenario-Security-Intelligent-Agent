# state.py - 状态定义兼容层
#
# 此文件保持向后兼容，所有定义从 state_types 和 state_v2 导入
#
# 使用方式:
#     from state import CTFState, VulnerabilityCandidate, AttackAction
#
# 新项目建议直接使用:
#     from state_v2 import CTFState
#     from state_types import VulnerabilityCandidate, AttackAction

# 从 state_v2 导入主状态类型
from state_v2 import CTFState, CTFStateV2

# 从 state_types 导入辅助类型
from state_types.web import (
    VulnerabilityCandidate,
    AttackAction,
    PageFeatures,
    Hint,
    ToolCall,
    NodeAttackStatus,
)

# 从 state_types 导入内网相关类型
from state_types.internal_network import (
    InternalHost,
    Credential,
    LateralMove,
)

# 从 state_types 导入规约器
from state_types.reducers import (
    cap_list_reducer,
    cap_results_reducer,
    cap_candidates_reducer,
    dedupe_list_reducer,
    merge_dict_reducer,
    visited_urls_reducer,
    visited_fingerprints_reducer,
    attack_results_reducer,
    tool_calls_reducer,
    failed_payloads_reducer,
    credentials_reducer,
    internal_hosts_reducer,
)

# 导出列表
__all__ = [
    # 主状态
    'CTFState',
    'CTFStateV2',

    # Web CTF 类型
    'VulnerabilityCandidate',
    'AttackAction',
    'PageFeatures',
    'Hint',
    'ToolCall',
    'NodeAttackStatus',

    # 内网类型
    'InternalHost',
    'Credential',
    'LateralMove',

    # 规约器
    'cap_list_reducer',
    'cap_results_reducer',
    'cap_candidates_reducer',
    'dedupe_list_reducer',
    'merge_dict_reducer',
    'visited_urls_reducer',
    'visited_fingerprints_reducer',
    'attack_results_reducer',
    'tool_calls_reducer',
    'failed_payloads_reducer',
    'credentials_reducer',
    'internal_hosts_reducer',
]