# app/state_types/cloud.py
"""
云安全攻击状态类型

适用于 Zone 2: 云安全专项攻击场景

使用 TypedDict 格式，与 CTFStateV2 组合模式兼容
"""

from typing import Annotated, List, Dict, Any, Optional
from typing_extensions import TypedDict
from .reducers import dedupe_list_reducer


class CloudSecurityState(TypedDict):
    """
    云安全攻击状态 - TypedDict 格式

    包含:
    - 云服务商识别
    - 元数据泄露
    - IAM 角色与凭据
    - 存储桶发现
    - 提权路径
    """

    # =========================================================================
    # 云服务商识别
    # =========================================================================
    cloud_mode: bool
    cloud_provider: str  # aws/azure/gcp/alibaba/tencent
    detected_services: Annotated[List[str], dedupe_list_reducer]

    # =========================================================================
    # 元数据泄露
    # =========================================================================
    metadata_leaked: Dict[str, Any]
    iam_roles: Annotated[List[str], dedupe_list_reducer]
    temp_credentials: Annotated[List[Dict], dedupe_list_reducer]

    # =========================================================================
    # 云函数
    # =========================================================================
    lambda_functions: Annotated[List[str], dedupe_list_reducer]
    lambda_env_vars: Dict[str, Dict[str, Any]]

    # =========================================================================
    # 存储桶
    # =========================================================================
    buckets_found: Annotated[List[str], dedupe_list_reducer]
    buckets_accessible: Annotated[List[str], dedupe_list_reducer]

    # =========================================================================
    # 提权路径
    # =========================================================================
    escalation_paths: Annotated[List[str], dedupe_list_reducer]
    current_privilege: str  # low/user/admin/root

    # =========================================================================
    # 攻击结果
    # =========================================================================
    cloud_attack_results: Annotated[List[Dict], dedupe_list_reducer]
    extracted_secrets: Dict[str, Any]

    # =========================================================================
    # 节点流转
    # =========================================================================
    cloud_phase: str  # recon/enum/exploit/escalate/complete