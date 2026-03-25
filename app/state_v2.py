# app/state_v2.py
"""
状态管理 V2 - 组合模式

将分散的状态类型组合为统一的 CTFState，同时保持向后兼容。

设计原则:
- 组合不继承：CTFState 由各场景状态组合而成
- 字段去重：公共字段只保留一份
- 向后兼容：现有代码无需修改
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict
import operator

# 从 state_types 导入类型定义
from state_types.base import BaseCTFState
from state_types.web import (
    WebCTFState, VulnerabilityCandidate, AttackAction,
    PageFeatures, Hint, ToolCall, NodeAttackStatus
)
from state_types.internal_network import (
    InternalNetworkState, InternalHost, Credential, LateralMove
)
from state_types.reducers import (
    cap_list_reducer, cap_candidates_reducer, cap_results_reducer,
    merge_dict_reducer, visited_urls_reducer
)


class CTFStateV2(TypedDict):
    """
    CTF 状态 V2 - 组合模式

    字段分类:
    - [B] Base: 基础字段（来自 BaseCTFState）
    - [W] Web: Web CTF 字段
    - [I] Internal: 内网渗透字段
    """
    # =====================================================
    # [B] 基础字段 - 所有场景共用
    # =====================================================
    task_name: str
    task_description: str
    target_url: str
    current_url: str
    start_time: float
    current_round: int
    execution_steps: int
    current_mode: Literal['exploit', 'explore', 'innovate', 'end', 'hitl']
    failure_weighted_score: float
    exploration_rounds: int
    rule_miss_count: int
    found_flag: bool
    final_flag: str
    visited_urls: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]
    scanned_ips: Annotated[List[str], lambda x, y: list(set(x + y))]
    scanned_urls: Annotated[List[str], lambda x, y: list(set(x + y))]
    attachments: List[Dict[str, Any]]

    # =====================================================
    # [W] Web CTF 字段
    # =====================================================
    page_features: PageFeatures
    raw_html_snippet: str
    baseline_response: Dict[str, Any]
    page_history: Dict[str, Dict[str, Any]]
    detected_scenes: Dict[str, Any]
    site_topology: Annotated[Dict[str, List[str]], lambda x, y: {**x, **y}]
    node_metadata: Annotated[Dict[str, Dict], lambda x, y: {**x, **y}]
    critical_nodes: List[str]
    attack_paths: List[List[str]]
    visited_fingerprints: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]
    vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer]
    permanent_rules: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 50)]
    tool_cache: Annotated[Dict[str, Any], lambda x, y: {**x, **y}]
    attack_batch: List[AttackAction]
    attack_results: Annotated[List[Dict], cap_results_reducer]
    tool_calls: Annotated[List[ToolCall], lambda x, y: cap_list_reducer(x, y, 100)]
    latest_tactical_guidance: Optional[str]
    analyst_intel: Optional[str]
    failed_payloads: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 50)]
    hint_level: int
    hint_history: Annotated[List[Hint], operator.add]
    last_intervention_step: int
    rag_context: List[str]
    temp_rules: List[Dict]
    success_trace: List[Dict]
    node_attack_status: Dict[str, NodeAttackStatus]
    successful_exploits: List[Dict]

    # =====================================================
    # [I] 内网渗透字段
    # =====================================================
    internal_network_detected: bool
    internal_network_range: str
    internal_hosts: Annotated[List[InternalHost], lambda x, y: x + y]
    credentials: Annotated[List[Credential], lambda x, y: x + y]
    lateral_moves: List[LateralMove]
    domain_info: Dict[str, Any]
    shell_session: Optional[Dict[str, Any]]
    active_sessions: List[Dict[str, Any]]
    tunnel_established: bool
    socks5_port: int
    uploaded_tools: List[str]
    privilege_level: str


# 向后兼容别名
CTFState = CTFStateV2