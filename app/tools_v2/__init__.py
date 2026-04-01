# Tools V2系统
#
# 借鉴Claude Code的buildTool工厂设计

from .tool_factory import (
    # 核心类
    CTFToolV2,
    ToolSchema,
    ParamSchema,
    ParamType,
    ValidationResult,
    ToolExecutionResult,
    ZodValidator,

    # 工厂函数
    buildTool,
    ensure_result_format,

    # 注册表
    ToolRegistryV2,
    get_tool_registry_v2,
    register_tool,
)

__all__ = [
    # 核心类
    "CTFToolV2",
    "ToolSchema",
    "ParamSchema",
    "ParamType",
    "ValidationResult",
    "ToolExecutionResult",
    "ZodValidator",

    # 工厂函数
    "buildTool",
    "ensure_result_format",

    # 注册表
    "ToolRegistryV2",
    "get_tool_registry_v2",
    "register_tool",
]