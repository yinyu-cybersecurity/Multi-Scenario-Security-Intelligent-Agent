# Agent类型系统
#
# 借鉴Claude Code设计，实现分层Agent架构

from .base import (
    AgentType,
    ToolPermission,
    AgentDefinition,
    EXPLORE_AGENT,
    PLAN_AGENT,
    ATTACK_AGENT,
    VERIFY_AGENT,
    COORDINATOR_AGENT,
    AGENT_REGISTRY,
    get_agent_definition,
    get_all_agent_types,
    get_agent_permissions,
    is_agent_read_only,
    check_tool_allowed,
)

__all__ = [
    # 枚举
    "AgentType",
    "ToolPermission",

    # 数据类
    "AgentDefinition",

    # 预定义Agent
    "EXPLORE_AGENT",
    "PLAN_AGENT",
    "ATTACK_AGENT",
    "VERIFY_AGENT",
    "COORDINATOR_AGENT",

    # 注册表
    "AGENT_REGISTRY",

    # 工具函数
    "get_agent_definition",
    "get_all_agent_types",
    "get_agent_permissions",
    "is_agent_read_only",
    "check_tool_allowed",
]