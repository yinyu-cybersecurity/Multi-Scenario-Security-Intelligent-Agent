# Tools V2系统
#
# 借鉴Claude Code的buildTool工厂设计
#
# 原生工具执行器 - 无Docker依赖

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

from .concurrency_config import (
    ConcurrencyLevel,
    ToolConcurrencyConfig,
    is_concurrency_safe,
    get_max_concurrent,
    classify_tools_for_parallel,
    is_read_only_command,
)

from .native_executor import (
    NativeExecutor,
    get_native_executor,
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

    # 并发安全
    "ConcurrencyLevel",
    "ToolConcurrencyConfig",
    "is_concurrency_safe",
    "get_max_concurrent",
    "classify_tools_for_parallel",
    "is_read_only_command",

    # 原生执行器
    "NativeExecutor",
    "get_native_executor",
]