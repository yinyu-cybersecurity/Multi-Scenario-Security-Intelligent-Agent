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
# 导入所有预定义的 reducer
from state_types.reducers import (
    visited_urls_reducer,
    visited_fingerprints_reducer,
    attack_results_reducer,
    tool_calls_reducer,
    failed_payloads_reducer,
    credentials_reducer,
    internal_hosts_reducer,
    cap_candidates_reducer,
    merge_dict_reducer,
    dedupe_list_reducer,
    _make_cap_reducer,
)

# 创建带特定上限的 reducer
_cap_50_reducer = _make_cap_reducer(50)
_cap_100_reducer = _make_cap_reducer(100)


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
    current_mode: Literal['exploit', 'explore', 'innovate', 'end']
    failure_weighted_score: float
    exploration_rounds: int
    rule_miss_count: int
    found_flag: bool
    final_flag: str
    visited_urls: Annotated[List[str], visited_urls_reducer]
    scanned_ips: Annotated[List[str], dedupe_list_reducer]
    scanned_urls: Annotated[List[str], dedupe_list_reducer]
    attachments: List[Dict[str, Any]]

    # =====================================================
    # [W] Web CTF 字段
    # =====================================================
    page_features: PageFeatures
    raw_html_snippet: str
    baseline_response: Dict[str, Any]
    page_history: Dict[str, Dict[str, Any]]
    detected_scenes: Dict[str, Any]
    site_topology: Annotated[Dict[str, List[str]], merge_dict_reducer]
    node_metadata: Annotated[Dict[str, Dict], merge_dict_reducer]
    critical_nodes: List[str]
    attack_paths: List[List[str]]
    topology_priority: List[tuple]  # 拓扑优先级: [(url, score), ...]
    visited_fingerprints: Annotated[List[str], visited_fingerprints_reducer]
    vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer]
    permanent_rules: Annotated[List[Dict], _cap_50_reducer]
    tool_cache: Annotated[Dict[str, Any], merge_dict_reducer]
    attack_batch: List[AttackAction]
    attack_results: Annotated[List[Dict], attack_results_reducer]
    tool_calls: Annotated[List[ToolCall], tool_calls_reducer]
    latest_tactical_guidance: Optional[str]
    analyst_intel: Optional[str]
    failed_payloads: Annotated[List[str], failed_payloads_reducer]
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
    internal_mode: bool  # 是否处于内网渗透模式
    internal_network_detected: bool
    internal_network_range: str
    internal_hosts: Annotated[List[InternalHost], internal_hosts_reducer]
    credentials: Annotated[List[Credential], credentials_reducer]
    lateral_moves: List[LateralMove]
    domain_info: Dict[str, Any]
    shell_session: Optional[Dict[str, Any]]
    active_sessions: List[Dict[str, Any]]
    tunnel_established: bool
    socks5_port: int
    uploaded_tools: List[str]
    privilege_level: str
    pivot_host: str  # 跳板机IP
    proxy_info: Optional[Dict[str, Any]]  # SOCKS5代理信息
    upload_status: str  # 工具上传状态: pending/completed/commands_generated/failed
    tunnel_status: str  # 隧道状态: pending/configured/failed
    post_exploit_status: str  # 后渗透状态: no_shell/ready_for_internal/web_only
    current_internal_target: str  # 当前内网目标IP

    # =====================================================
    # [I] 内网渗透扩展字段 - 多主机Flag搜索
    # =====================================================
    found_flags: Annotated[List[str], dedupe_list_reducer]  # 所有发现的flag
    compromised_hosts: Annotated[List[str], dedupe_list_reducer]  # 已攻陷的主机IP
    current_compromise_phase: str  # 当前阶段: flag_search/lateral_move/complete


# 向后兼容别名
CTFState = CTFStateV2