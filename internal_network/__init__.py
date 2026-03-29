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
- nodes.py: 内网侦察节点、横向移动节点、权限提升节点、凭据收集节点、Flag搜索节点
- orchestrator.py: 内网渗透编排器
- prompts.py: 内网渗透提示词模块
- advanced_operations.py: 高级操作（提权、文件传输、凭据转储）
- strategic_planner.py: AI驱动的战略规划器（第三赛区核心改进）

目标:
1. 外网打点获取初始Flag
2. 攻陷所有内网主机
3. 在每台主机的管理员文件夹中搜索Flag
"""

from .nodes import (
    internal_recon_node,
    lateral_move_node,
    privilege_escalation_node,
    credential_gather_node,
    flag_search_node,
    get_next_internal_target
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
from .strategic_planner import (
    strategic_planner_node,
    StrategicPlanner,
    AttackPriority,
    get_strategic_planner
)

__all__ = [
    # 节点
    'internal_recon_node',
    'lateral_move_node',
    'privilege_escalation_node',
    'credential_gather_node',
    'flag_search_node',
    # 辅助函数
    'get_next_internal_target',
    # 编排器
    'InternalNetworkOrchestrator',
    # 提示词
    'get_internal_recon_prompt',
    'get_credential_analysis_prompt',
    'get_lateral_move_prompt',
    'get_ad_analysis_prompt',
    'get_privilege_escalation_prompt',
    'get_internal_mode_router_prompt',
    # 战略规划器（第三赛区核心改进）
    'strategic_planner_node',
    'StrategicPlanner',
    'AttackPriority',
    'get_strategic_planner'
]