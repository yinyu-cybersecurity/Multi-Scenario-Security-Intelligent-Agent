# internal_network/__init__.py
"""
内网渗透模块 - 可选扩展

本模块提供内网渗透能力，不影响原有Web CTF功能。
通过配置 internal_mode=True 启用。

设计原则:
1. 独立于原有架构
2. 可选启用
3. 共享CTFState状态

模块组成:
- nodes.py: 内网侦察节点、横向移动节点、权限提升节点、凭据收集节点
- orchestrator.py: 内网渗透编排器
- prompts.py: 内网渗透提示词模块
- advanced_operations.py: 高级操作（提权、文件传输、凭据转储）
"""

from .nodes import (
    internal_recon_node,
    lateral_move_node,
    privilege_escalation_node,
    credential_gather_node
)
from .orchestrator import InternalNetworkOrchestrator
from .prompts import (
    get_internal_recon_prompt,
    get_credential_analysis_prompt,
    get_lateral_move_prompt,
    get_ad_analysis_prompt,
    get_privilege_escalation_prompt,
    get_internal_mode_router_prompt
)

__all__ = [
    # 节点
    'internal_recon_node',
    'lateral_move_node',
    'privilege_escalation_node',
    'credential_gather_node',
    # 编排器
    'InternalNetworkOrchestrator',
    # 提示词
    'get_internal_recon_prompt',
    'get_credential_analysis_prompt',
    'get_lateral_move_prompt',
    'get_ad_analysis_prompt',
    'get_privilege_escalation_prompt',
    'get_internal_mode_router_prompt'
]