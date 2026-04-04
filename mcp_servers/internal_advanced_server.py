# mcp_servers/internal_advanced_server.py
"""内网高级工具MCP服务器 - frp配置生成, fscan路径查询"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import json
import os

server = Server("ctf-internal-advanced")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="frp_config", description="生成frp客户端配置文件", inputSchema={
            "type": "object",
            "properties": {
                "server_addr": {"type": "string", "description": "frp服务器地址"},
                "server_port": {"type": "integer", "default": 7000},
                "local_ip": {"type": "string", "default": "127.0.0.1"},
                "local_port": {"type": "integer"},
                "remote_port": {"type": "integer"},
            },
            "required": ["server_addr", "local_port", "remote_port"]
        }),
        Tool(name="frp_path", description="获取frp工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="fscan_linux_path", description="获取fscan_linux工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="fscan_windows_path", description="获取fscan_windows工具路径", inputSchema={"type": "object", "properties": {}}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "frp_config":
        config = f"""[common]
server_addr = {arguments['server_addr']}
server_port = {arguments.get('server_port', 7000)}

[tunnel]
type = tcp
local_ip = {arguments.get('local_ip', '127.0.0.1')}
local_port = {arguments['local_port']}
remote_port = {arguments['remote_port']}
"""
        return [TextContent(type="text", text=config)]

    elif name == "frp_path":
        return [TextContent(type="text", text=f"frpc路径: {THIRDPARTY}/frp/frpc\n使用方式: 上传到目标机器后执行")]

    elif name == "fscan_linux_path":
        return [TextContent(type="text", text=f"fscan路径: {THIRDPARTY}/fscan_linux/fscan\n使用方式: chmod +x && ./fscan -h <target>")]

    elif name == "fscan_windows_path":
        return [TextContent(type="text", text=f"fscan.exe路径: {THIRDPARTY}/fscan_windows/fscan.exe\n使用方式: 上传到目标机器后执行")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())