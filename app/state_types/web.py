# app/state_types/web.py
"""
Web CTF 场景状态

Web 渗透测试专用的状态字段。
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict, NotRequired
from .base import BaseCTFState
from .reducers import (
    cap_candidates_reducer,
    cap_list_reducer,
    merge_dict_reducer,
    visited_urls_reducer,
    visited_fingerprints_reducer,
    attack_results_reducer,
    tool_calls_reducer,
    failed_payloads_reducer,
)


class VulnerabilityCandidate(TypedDict):
    """
    潜在漏洞点

    分析兵识别出可能存在的漏洞，但不生成具体 Payload。

    Attributes:
        type: 漏洞类型, e.g., 'sqli', 'rce', 'lfi', 'xss', 'ssrf'
        location: 漏洞位置, e.g., 'param:id', 'header:User-Agent'
        confidence: 置信度 0-1
        context: 上下文信息
        recommended_tools: 推荐使用的工具列表
        url: 漏洞归属的 URL
        retrieved_knowledge: 从知识库检索的相关资料（可选）
        reason: 判断理由（可选）
    """
    type: str
    location: str
    confidence: float
    context: Dict[str, Any]
    recommended_tools: List[str]
    url: str
    # 可选字段
    retrieved_knowledge: NotRequired[List[Dict[str, Any]]]
    reason: NotRequired[str]


class AttackAction(TypedDict):
    """
    具体攻击动作

    直接对应一次工具调用或 Payload 发送。

    Attributes:
        id: 动作唯一标识
        tool: 使用的工具名
        target: 目标 URL 或参数
        payload: 具体 Payload 内容
        params: 工具参数
        priority: 执行优先级 0-1
        timeout: 超时时间（秒）
    """
    id: str
    tool: str
    target: str
    payload: str
    params: Dict[str, Any]
    priority: float
    timeout: int


class HtmlExtraction(TypedDict):
    """
    结构化HTML提取数据

    在HTML截断之前提取的关键信息，防止丢失攻击面。

    Attributes:
        hidden_fields: 所有隐藏字段 {'name': 'value'}
        form_endpoints: 表单端点列表 [{'action': str, 'method': str, 'fields': [str]}]
        script_endpoints: JavaScript中发现的URL/端点
        comments: HTML注释内容（可能包含提示）
        meta_tags: Meta标签内容 {'name': 'content'}
        data_attributes: data-*属性值
        api_endpoints: API端点（从JS/fetch/ajax中提取）
    """
    hidden_fields: Dict[str, str]
    form_endpoints: List[Dict[str, Any]]
    script_endpoints: List[str]
    comments: List[str]
    meta_tags: Dict[str, str]
    data_attributes: Dict[str, str]
    api_endpoints: List[str]


class PageFeatures(TypedDict):
    """
    页面特征向量

    将原始 HTML 压缩为关键特征，减少 Token 消耗。

    Attributes:
        tech_stack: 技术栈
        input_vectors: 可控输入点
        sensitive_paths: 发现的敏感路径
        dom_structure_hash: DOM 结构哈希
        form_structure: 表单结构详情
        scripts: JS 文件列表
        cookies: Cookie 信息
        headers: 响应头
        html_extraction: 结构化HTML提取数据（在截断前提取）
    """
    tech_stack: List[str]
    input_vectors: List[str]
    sensitive_paths: List[str]
    dom_structure_hash: str
    form_structure: List[Dict[str, Any]]
    scripts: List[str]
    cookies: Dict[str, str]
    headers: Dict[str, str]
    html_extraction: HtmlExtraction


class Hint(TypedDict):
    """
    提示信息

    记录人类或 AI 给出的提示。

    Attributes:
        level: 提示级别 1-3
        content: 提示内容
        source: 来源 ('ai' 或 'human')
        timestamp: 时间戳
    """
    level: int
    content: str
    source: Literal['ai', 'human']
    timestamp: float


class ToolCall(TypedDict):
    """
    工具调用记录

    Attributes:
        tool_name: 工具名称
        params: 调用参数
        result: 执行结果
        cached: 是否命中缓存
        duration: 执行耗时（秒）
    """
    tool_name: str
    params: Dict[str, Any]
    result: Any
    cached: bool
    duration: float


class NodeAttackStatus(TypedDict):
    """
    节点攻击状态

    记录每个被攻击节点的实时状态，防止卡死。

    Attributes:
        status: 当前状态
        start_time: 开始攻击时间戳
        last_decision_time: 上次问 AI 的时间戳
        attempt_count: 已尝试次数
        last_status_codes: 最近几次的状态码
        ai_decision_log: AI 的历史决策记录
    """
    status: Literal["active", "abandoned", "success"]
    start_time: float
    last_decision_time: float
    attempt_count: int
    last_status_codes: List[int]
    ai_decision_log: List[Dict[str, Any]]


class WebCTFState(TypedDict):
    """
    Web CTF 场景状态

    包含 Web 渗透测试所需的所有字段。

    继承自 BaseCTFState，添加:
    - 页面感知字段
    - 拓扑结构字段
    - 记忆与知识字段
    - 执行流字段
    - 决策状态字段
    """

    # =========================================================================
    # 继承基础字段
    # =========================================================================
    # task_name, target_url, current_url, start_time, current_round,
    # execution_steps, current_mode, failure_weighted_score, found_flag, etc.

    # =========================================================================
    # 页面感知
    # =========================================================================

    # 页面特征向量
    page_features: PageFeatures

    # 关键 HTML 片段
    raw_html_snippet: str

    # 初始页面基准
    baseline_response: Dict[str, Any]

    # 页面变更历史
    page_history: Dict[str, Dict[str, Any]]

    # 场景检测结果
    detected_scenes: Dict[str, Any]

    # =========================================================================
    # 拓扑结构
    # =========================================================================

    # 站点拓扑图（邻接表）
    site_topology: Annotated[Dict[str, List[str]], merge_dict_reducer]

    # 节点属性
    node_metadata: Annotated[Dict[str, Dict], merge_dict_reducer]

    # 关键节点列表
    critical_nodes: List[str]

    # 发现的攻击路径
    attack_paths: List[List[str]]

    # =========================================================================
    # 记忆与知识
    # =========================================================================

    # 页面指纹历史（去重）
    visited_fingerprints: Annotated[List[str], visited_fingerprints_reducer]

    # 漏洞候选项（智能去重）
    vuln_candidates: Annotated[List[VulnerabilityCandidate], cap_candidates_reducer]

    # 永久规则
    permanent_rules: Annotated[List[Dict], lambda x, y: cap_list_reducer(x, y, 50)]

    # 工具执行缓存
    tool_cache: Annotated[Dict[str, Any], merge_dict_reducer]

    # 已知事实
    known_facts: str

    # =========================================================================
    # 执行流
    # =========================================================================

    # 当前批次的攻击任务
    attack_batch: List[AttackAction]

    # 攻击结果日志
    attack_results: Annotated[List[Dict], attack_results_reducer]

    # 工具调用记录
    tool_calls: Annotated[List[ToolCall], tool_calls_reducer]

    # 最新战术指引
    latest_tactical_guidance: Optional[str]

    # 分析兵情报
    analyst_intel: Optional[str]

    # 失败的 payload 列表
    failed_payloads: Annotated[List[str], failed_payloads_reducer]

    # =========================================================================
    # 决策状态
    # =========================================================================

    # 节点攻击状态
    node_attack_status: Dict[str, NodeAttackStatus]

    # 场景聚焦
    focused_scene: str
    scene_attack_attempts: int
    scene_exhausted: bool

    # =========================================================================
    # RAG 与进化
    # =========================================================================

    # RAG 检索到的参考知识
    rag_context: List[str]

    # 临时规则
    temp_rules: List[Dict]

    # 成功路径回溯
    success_trace: List[Dict]