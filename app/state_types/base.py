# app/state_types/base.py
"""
基础状态定义

所有 CTF 场景的通用状态字段。

设计原则:
- 只包含所有场景都需要的字段
- 保持最小化，避免冗余
"""

from typing import Annotated, List, Dict, Literal, Any, Optional
from typing_extensions import TypedDict
from .reducers import cap_list_reducer


class BaseCTFState(TypedDict):
    """
    基础 CTF 状态 - 所有场景共有的字段

    包含:
    - 任务基本信息
    - 执行控制字段
    - 结果状态字段
    """

    # =========================================================================
    # 任务基本信息
    # =========================================================================

    # 题目名称
    task_name: str

    # 题目描述
    task_description: str

    # 初始目标 URL（Web CTF）或文件路径（Pwn/Reverse）
    target_url: str

    # 当前处理的 URL/目标
    current_url: str

    # 任务开始时间戳
    start_time: float

    # =========================================================================
    # 执行控制字段
    # =========================================================================

    # 当前执行轮次
    current_round: int

    # 总执行步数
    execution_steps: int

    # 当前工作模式
    current_mode: Literal['exploit', 'explore', 'innovate', 'end', 'hitl']

    # 失败加权分数（用于模式切换决策）
    failure_weighted_score: float

    # 探索模式已执行轮次
    exploration_rounds: int

    # 规则引擎连续未命中次数
    rule_miss_count: int

    # =========================================================================
    # 结果状态字段
    # =========================================================================

    # 是否找到 flag
    found_flag: bool

    # 最终 flag 内容
    final_flag: str

    # 已访问的 URL 列表（去重）
    visited_urls: Annotated[List[str], lambda x, y: cap_list_reducer(x, y, 100)]

    # 已扫描的 IP 列表
    scanned_ips: Annotated[List[str], lambda x, y: list(set(x + y))]

    # 已扫描的 URL 列表
    scanned_urls: Annotated[List[str], lambda x, y: list(set(x + y))]

    # 附件列表
    attachments: List[Dict[str, Any]]


class ExecutionStatus(TypedDict):
    """执行状态 - 用于监控和调试"""

    # 当前状态
    status: Literal['pending', 'running', 'paused', 'completed', 'failed', 'timeout']

    # 当前执行的节点
    current_node: str

    # 已访问的节点列表
    visited_nodes: List[str]

    # 错误信息
    error: str

    # 进度百分比
    progress: float


class ResultSummary(TypedDict):
    """结果摘要 - 用于最终报告"""

    # 是否成功
    success: bool

    # 找到的 flag
    flag: str

    # 执行时间（秒）
    duration: float

    # 总步数
    total_steps: int

    # 发现的漏洞数量
    vulns_found: int

    # 获取的凭据数量
    creds_found: int