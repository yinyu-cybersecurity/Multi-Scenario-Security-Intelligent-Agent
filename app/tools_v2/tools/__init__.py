"""
CTF安全工具 - 简化MCP风格

架构：
- JSON Schema定义工具参数
- 简单async handler执行命令
- 统一执行入口
"""

from .simple_tools import (
    TOOL_SCHEMAS,
    HANDLERS,
    get_tool_schema,
    list_tools,
    get_all_schemas,
    execute_tool,
    nmap_handler,
    nuclei_handler,
    httpx_handler,
    fscan_handler,
    sqlmap_handler,
)

__all__ = [
    # Schema
    "TOOL_SCHEMAS",
    "HANDLERS",

    # API
    "get_tool_schema",
    "list_tools",
    "get_all_schemas",
    "execute_tool",

    # Handlers
    "nmap_handler",
    "nuclei_handler",
    "httpx_handler",
    "fscan_handler",
    "sqlmap_handler",
]


def register_tools(registry):
    """
    注册工具到Registry（兼容旧接口）

    现在工具通过JSON Schema直接定义，
    此函数保持向后兼容
    """
    from app.tools_v2.tool_factory import buildTool, get_tool_registry_v2
    from app.agents.base import ToolPermission

    # 如果传入None，使用全局registry
    if registry is None:
        registry = get_tool_registry_v2()

    # 为每个工具创建CTFToolV2包装（兼容）
    for name, schema in TOOL_SCHEMAS.items():
        handler = HANDLERS.get(name)
        if handler:
            # 转换参数格式
            params = []
            props = schema["inputSchema"].get("properties", {})
            required = schema["inputSchema"].get("required", [])

            for pname, pschema in props.items():
                params.append({
                    "name": pname,
                    "type": pschema.get("type", "string"),
                    "required": pname in required,
                    "description": pschema.get("description", ""),
                    "default": pschema.get("default"),
                    "enum": pschema.get("enum"),
                    "min": pschema.get("minimum"),
                    "max": pschema.get("maximum"),
                    "format": pschema.get("format")
                })

            # 创建包装handler
            async def wrapped_handler(params, context, h=handler):
                return await h(**params)

            tool = buildTool(
                name=name,
                description=schema["description"],
                parameters=params,
                handler=wrapped_handler,
                permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
                timeout=300
            )
            registry.register(tool)