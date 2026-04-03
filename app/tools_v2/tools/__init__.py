"""
CTF安全工具 - 简化版

设计原则：
1. 工具Schema仅包含元数据（名称、描述、分类、示例）
2. 工具路径由tool_paths.py管理
3. 工具执行由native_executor处理
4. AI通过skill文档了解工具用法，直接调用Bash执行
"""

from .simple_tools import (
    TOOL_SCHEMAS,
    HANDLERS,
    get_tool_schema,
    list_tools,
    get_all_schemas,
    validate_target,
    validate_url_for_ssrf,
    validate_ports,
)

__all__ = [
    # Schema
    "TOOL_SCHEMAS",
    "HANDLERS",

    # API
    "get_tool_schema",
    "list_tools",
    "get_all_schemas",

    # 安全验证
    "validate_target",
    "validate_url_for_ssrf",
    "validate_ports",
]


def register_tools(registry):
    """
    注册工具到Registry（兼容旧接口）

    注意：简化版本不使用handler，工具通过Bash直接调用
    此函数仅注册工具元数据
    """
    from app.tools_v2.tool_factory import buildTool, get_tool_registry_v2, ParamType
    from app.agents.base import ToolPermission

    # 如果传入None，使用全局registry
    if registry is None:
        registry = get_tool_registry_v2()

    # 为每个工具注册元数据（无handler - 使用空的handler）
    async def empty_handler(params, context):
        return {"success": True, "message": "Tool metadata only"}

    for name, schema in TOOL_SCHEMAS.items():
        # 使用buildTool创建正确的CTFToolV2对象
        tool = buildTool(
            name=name,
            description=schema.get("description", ""),
            parameters=[
                {
                    "name": "args",
                    "type": "string",
                    "required": False,
                    "description": "命令参数"
                }
            ],
            handler=empty_handler,
            permissions=[],  # 空权限列表
        )
        registry.register(tool)