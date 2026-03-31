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
from state_types.strategic import StrategicContext
from state_types.web import (
    VulnerabilityCandidate, AttackAction,
    PageFeatures, Hint, ToolCall, NodeAttackStatus
)
from state_types.internal_network import (
    InternalHost, Credential
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
    generic_list_reducer_20,
    generic_list_reducer_50,
    generic_list_reducer_100,
)

# 创建带特定上限的 reducer
_cap_50_reducer = _make_cap_reducer(50)
_cap_100_reducer = _make_cap_reducer(100)

# 从 config 导入配置
from config import config


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
    current_mode: Literal['exploit', 'end']
    found_flag: bool
    final_flag: str
    visited_urls: Annotated[List[str], visited_urls_reducer]
    scanned_ips: Annotated[List[str], dedupe_list_reducer]
    scanned_urls: Annotated[List[str], dedupe_list_reducer]
    attachments: Annotated[List[Dict[str, Any]], _make_cap_reducer(config.MAX_ATTACHMENTS)]

    # =====================================================
    # [S] 战略上下文字段 - AI思维框架
    # =====================================================
    strategic_context: Dict[str, Any]  # StrategicContext结构
    active_modules: List[str]  # 当前激活的模块列表
    memory_mode: str  # 当前内存模式: "minimal"/"web"/"internal"/"cloud"/"ai"

    # [断点8修复] AI决策链累积字段
    strategic_decisions: Annotated[List[Dict[str, Any]], generic_list_reducer_50]  # AI决策历史记录
    # 每个决策记录格式: {
    #     "timestamp": float,
    #     "node": str,  # 来源节点
    #     "decision_type": str,  # attack/route/mode_switch/privesc
    #     "action": str,  # 具体行动
    #     "reason": str,  # 决策理由
    #     "confidence": float,  # 置信度
    #     "outcome": str,  # 执行结果: success/failed/pending
    # }

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
    critical_nodes: Annotated[List[str], _make_cap_reducer(config.MAX_CRITICAL_NODES)]
    attack_paths: Annotated[List[List[str]], _make_cap_reducer(config.MAX_ATTACK_PATHS)]
    topology_priority: List[tuple]  # 拓扑优先级: [(url, score), ...]
    visited_fingerprints: Annotated[List[str], visited_fingerprints_reducer]
    vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer]
    permanent_rules: Annotated[List[Dict], _cap_50_reducer]
    tool_cache: Annotated[Dict[str, Any], merge_dict_reducer]
    attack_batch: List[AttackAction]  # 单次攻击批次，无需reducer
    attack_results: Annotated[List[Dict], attack_results_reducer]
    attack_summary: str  # [断点4修复] 攻击历史摘要（关键发现压缩，防止截断丢失）
    tool_calls: Annotated[List[ToolCall], tool_calls_reducer]
    latest_tactical_guidance: Optional[str]
    # [断点1修复] 结构化战术指导字段
    guidance_type: str  # switch_scene/continue/deepen/abort
    enforce_change: bool  # 是否强制执行指导
    guidance_reason: str  # 战术指导的原因
    guidance_target_url: str  # 战术指导建议的目标URL
    analyst_intel: Optional[str]
    failed_payloads: Annotated[List[str], failed_payloads_reducer]
    fallback_plans: Annotated[List[Dict[str, Any]], _make_cap_reducer(config.MAX_FALLBACK_PLANS)]
    hint_level: int
    hint_history: Annotated[List[Hint], operator.add]
    rag_context: List[str]  # RAG上下文，单次使用，无需reducer
    temp_rules: Annotated[List[Dict], generic_list_reducer_20]
    success_trace: Annotated[List[Dict], generic_list_reducer_50]
    node_attack_status: Dict[str, NodeAttackStatus]

    # =====================================================
    # [W] 场景聚焦字段 (用于深度攻击)
    # =====================================================
    known_facts: str  # 已知事实，由 verifier 积累
    focused_scene: str  # 当前聚焦场景，如 "Spring", "Tomcat/9.0.30"
    scene_attack_attempts: int  # 当前场景攻击尝试次数
    scene_exhausted: bool  # 当前场景是否已穷尽

    # =====================================================
    # [I] 内网渗透字段
    # =====================================================
    internal_mode: bool  # 是否处于内网渗透模式
    internal_network_range: str
    internal_hosts: Annotated[List[InternalHost], internal_hosts_reducer]
    credentials: Annotated[List[Credential], credentials_reducer]
    domain_info: Dict[str, Any]
    # [简化] 合并会话相关字段：移除shell_session，统一使用active_sessions
    active_sessions: Annotated[List[Dict[str, Any]], _make_cap_reducer(config.MAX_ACTIVE_SESSIONS)]
    socks5_port: int
    uploaded_tools: Annotated[List[str], _make_cap_reducer(config.MAX_UPLOADED_TOOLS)]
    pivot_host: str  # 跳板机IP
    proxy_info: Optional[Dict[str, Any]]  # SOCKS5代理信息
    upload_status: str  # 工具上传状态: pending/completed/commands_generated/failed
    tunnel_status: str  # 隧道状态: pending/configured/failed
    post_exploit_status: str  # 后渗透状态: no_shell/ready_for_internal/web_only
    current_internal_target: str  # 当前内网目标IP

    # [I] 内网渗透 - AD域字段
    domain_controller: str  # 域控IP
    ad_domain: str  # AD域名
    ad_users: Annotated[List[str], dedupe_list_reducer]
    ad_groups: Annotated[List[str], dedupe_list_reducer]
    ad_computers: Annotated[List[str], dedupe_list_reducer]
    ad_trusts: Annotated[List[Dict], dedupe_list_reducer]
    lateral_movement_paths: Annotated[List[Dict], dedupe_list_reducer]

    # =====================================================
    # [W] 漏洞利用增强字段
    # =====================================================
    exploit_keywords: Dict[str, Any]  # 检索关键词: {cve_ids, framework, version, tags}
    continue_attack: bool  # 是否继续攻击
    remaining_payloads: List[Dict[str, Any]]  # 待尝试的payload列表

    # =====================================================
    # [I] 内网渗透扩展字段 - 多主机Flag搜索
    # =====================================================
    found_flags: Annotated[List[str], dedupe_list_reducer]  # 所有发现的flag
    # [简化] 移除compromised_hosts和failed_lateral_hosts，状态由internal_hosts.status管理
    current_compromise_phase: str  # 当前阶段: flag_search/lateral_move/complete
    persistence_established: bool  # 是否已建立持久化
    persistence_results: Annotated[List[Dict[str, Any]], _make_cap_reducer(config.MAX_PERSISTENCE_RESULTS)]  # 持久化结果记录

    # =====================================================
    # [C] 云安全字段
    # =====================================================
    cloud_mode: bool
    cloud_provider: str  # aws/azure/gcp/alibaba/tencent
    metadata_leaked: Dict[str, Any]
    iam_roles: Annotated[List[str], dedupe_list_reducer]
    temp_credentials: Annotated[List[Dict], dedupe_list_reducer]
    buckets_found: Annotated[List[str], dedupe_list_reducer]
    escalation_paths: Annotated[List[str], dedupe_list_reducer]
    cloud_phase: str  # recon/enum/exploit/escalate/complete

    # =====================================================
    # [A] AI安全字段
    # =====================================================
    ai_mode: bool
    target_model: str  # openai/anthropic/deepseek
    target_endpoint: str
    detected_ai_type: str
    prompt_injection_success: bool
    jailbreak_success: bool
    successful_payloads: Annotated[List[str], dedupe_list_reducer]
    leaked_system_prompt: str
    ai_phase: str  # detect/probe/exploit/exfiltrate/complete

    # =====================================================
    # [Crypto] 密码学 CTF 字段
    # =====================================================
    crypto_mode: bool
    crypto_analysis: Dict[str, Any]
    identified_ciphertexts: Annotated[List[Dict[str, Any]], generic_list_reducer_50]
    decrypted_data: Annotated[List[str], generic_list_reducer_50]
    potential_flags: Annotated[List[str], dedupe_list_reducer]

    # =====================================================
    # [Pwn] 二进制漏洞利用字段
    # =====================================================
    pwn_mode: bool
    binary_path: str
    binary_info: Dict[str, Any]
    vulnerabilities: Annotated[List[Dict[str, Any]], generic_list_reducer_20]
    exploit_script: str
    exploit_info: Dict[str, Any]
    pwn_analysis: Dict[str, Any]

    # =====================================================
    # [Reverse] 逆向工程字段
    # =====================================================
    reverse_mode: bool
    reverse_info: Dict[str, Any]
    decompiled_code: str
    algorithm_type: str
    key_findings: str
    functions: Annotated[List[Dict[str, Any]], generic_list_reducer_100]
    extracted_strings: Annotated[List[str], generic_list_reducer_100]

    # =====================================================
    # [Misc] 杂项 CTF 字段
    # =====================================================
    misc_mode: bool
    misc_file: str
    file_info: Dict[str, Any]
    steg_results: Dict[str, Any]
    media_analysis: Dict[str, Any]
    misc_analysis: Dict[str, Any]
    extracted_data: Annotated[List[Any], generic_list_reducer_50]
    embedded_files: Annotated[List[str], generic_list_reducer_50]


# 向后兼容别名
CTFState = CTFStateV2


def get_default_state(task_name: str, task_description: str, target_url: str) -> dict:
    """
    从类型注解自动生成默认状态

    Args:
        task_name: 任务名称
        task_description: 任务描述
        target_url: 目标URL

    Returns:
        包含所有字段默认值的字典
    """
    import time
    from typing import get_origin, get_args
    from typing_extensions import TypedDict  # [修复] 导入TypedDict用于类型检查

    # 基本类型默认值映射
    defaults = {
        str: "",
        int: 0,
        float: 0.0,
        bool: False,
    }

    state = {}

    for field_name, field_type in CTFStateV2.__annotations__.items():
        origin = get_origin(field_type)
        if origin is Annotated:
            inner_type = get_args(field_type)[0]
        else:
            inner_type = field_type

        # 处理容器类型
        if inner_type == list or (hasattr(inner_type, '__origin__') and inner_type.__origin__ == list):
            state[field_name] = []
        elif inner_type == dict or (hasattr(inner_type, '__origin__') and inner_type.__origin__ == dict):
            state[field_name] = {}
        # [修复] TypedDict类型应该返回空字典，而不是None
        elif isinstance(inner_type, type) and issubclass(inner_type, dict):
            # TypedDict是dict的子类，返回空字典
            state[field_name] = {}
        elif inner_type in defaults:
            state[field_name] = defaults[inner_type]
        else:
            # Optional或其他类型默认为None
            state[field_name] = None

    # 覆盖必需字段
    state.update({
        "task_name": task_name,
        "task_description": task_description,
        "target_url": target_url,
        "current_url": target_url,
        "start_time": time.time(),
        "current_mode": "exploit",
        # 战略上下文字段默认值
        "strategic_context": {},
        "active_modules": ["app.llm_client", "app.logger", "app.config"],
        "memory_mode": "minimal",  # 初始minimal，由类型检测器决定实际模式
        # [断点8修复] strategic_decisions默认值
        "strategic_decisions": [],
    })

    return state