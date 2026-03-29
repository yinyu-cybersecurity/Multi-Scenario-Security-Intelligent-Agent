# app/state_types/__init__.py
"""
状态类型模块

提供模块化的状态类型定义，与原有 state.py 共存。

使用方式:
    # 原有方式（不变）
    from state import CTFState

    # 新方式（场景分离）
    from state_types.web import WebCTFState
    from state_types.internal_network import InternalNetworkState
"""

# 导出规约器
from .reducers import (
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

# 导出基础状态
from .base import BaseCTFState, ExecutionStatus, ResultSummary

# 导出场景状态
from .web import (
    WebCTFState,
    VulnerabilityCandidate,
    AttackAction,
    PageFeatures,
    Hint,
    ToolCall,
    NodeAttackStatus,
    HtmlExtraction,
)

from .internal_network import (
    InternalNetworkState,
    InternalHost,
    Credential,
    LateralMove,
)

from .crypto import (
    CryptoCTFState,
    RSAParams,
    CryptoCipher,
)

from .pwn import (
    PwnCTFState,
    BinaryInfo,
    GadgetInfo,
    ExploitScript,
)

from .reverse import (
    ReverseCTFState,
    FunctionInfo,
    StringInfo,
    AntiDebugTechnique,
)

from .misc import (
    MiscCTFState,
    StegInfo,
    MediaAnalysis,
    ForensicInfo,
)


__all__ = [
    # 规约器
    'cap_list_reducer',
    'cap_candidates_reducer',

    # 基础状态
    'BaseCTFState',
    'ExecutionStatus',
    'ResultSummary',

    # Web CTF 状态
    'WebCTFState',
    'VulnerabilityCandidate',
    'AttackAction',
    'PageFeatures',
    'Hint',
    'ToolCall',
    'NodeAttackStatus',
    'HtmlExtraction',

    # 内网渗透状态
    'InternalNetworkState',
    'InternalHost',
    'Credential',
    'LateralMove',

    # 密码学 CTF 状态
    'CryptoCTFState',
    'RSAParams',
    'CryptoCipher',

    # Pwn CTF 状态
    'PwnCTFState',
    'BinaryInfo',
    'GadgetInfo',
    'ExploitScript',

    # 逆向 CTF 状态
    'ReverseCTFState',
    'FunctionInfo',
    'StringInfo',
    'AntiDebugTechnique',

    # Misc CTF 状态
    'MiscCTFState',
    'StegInfo',
    'MediaAnalysis',
    'ForensicInfo',
]