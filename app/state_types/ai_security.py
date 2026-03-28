# app/state_types/ai_security.py
"""
AI安全攻击状态类型

适用于 Zone 2: AI基础设施漏洞场景

使用 TypedDict 格式，与 CTFStateV2 组合模式兼容
"""

from typing import Annotated, List, Dict, Any, Optional
from typing_extensions import TypedDict
from .reducers import dedupe_list_reducer


class AISecurityState(TypedDict):
    """
    AI安全攻击状态 - TypedDict 格式

    包含:
    - 目标识别
    - 防护检测
    - 攻击结果
    - 信息泄露
    - 模型窃取
    """

    # =========================================================================
    # 目标识别
    # =========================================================================
    target_model: str  # gpt-4/claude/deepseek/custom
    target_endpoint: str  # API端点
    detected_ai_type: str  # chatbot/agent/assistant/embedding

    # =========================================================================
    # 防护检测
    # =========================================================================
    detected_protections: Annotated[List[str], dedupe_list_reducer]
    # 例如: ["content_filter", "prompt_injection_defense", "rate_limit"]

    # =========================================================================
    # 攻击结果
    # =========================================================================
    prompt_injection_success: bool
    jailbreak_success: bool
    successful_payloads: Annotated[List[str], dedupe_list_reducer]

    # =========================================================================
    # 信息泄露
    # =========================================================================
    leaked_system_prompt: str
    leaked_training_data: Annotated[List[str], dedupe_list_reducer]
    extracted_context: Dict[str, Any]

    # =========================================================================
    # 模型窃取
    # =========================================================================
    model_extraction_progress: float  # 0-1
    extracted_parameters: Dict[str, Any]

    # =========================================================================
    # 攻击历史
    # =========================================================================
    attack_attempts: Annotated[List[Dict], dedupe_list_reducer]
    ai_attack_results: Annotated[List[Dict], dedupe_list_reducer]

    # =========================================================================
    # 节点流转
    # =========================================================================
    ai_phase: str  # detect/probe/exploit/exfiltrate/complete