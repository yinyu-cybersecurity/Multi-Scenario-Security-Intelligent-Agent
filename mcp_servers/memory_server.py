# mcp_servers/memory_server.py
"""记忆工具MCP服务器 - remember, recall"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import json

server = Server("ctf-memory")
_memory = {}

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="remember",
            description="记录发现",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "键"},
                    "value": {"type": "string", "description": "值"},
                },
                "required": ["key", "value"]
            }
        ),
        Tool(
            name="recall",
            description="回忆发现",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "键（可选）"},
                }
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "remember":
        _memory[arguments["key"]] = arguments["value"]
        return [TextContent(type="text", text=f"已记录: {arguments['key']}")]
    elif name == "recall":
        key = arguments.get("key")
        if key:
            value = _memory.get(key, "未找到")
            return [TextContent(type="text", text=f"{key}: {value}")]
        else:
            return [TextContent(type="text", text=json.dumps(_memory, indent=2, ensure_ascii=False))]
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())