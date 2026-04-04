# mcp_servers/binary_server.py
"""二进制工具MCP服务器 - binary_tools"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-binary")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="binary_tools_path", description="获取二进制工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="binary_analysis", description="二进制分析", inputSchema={
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "工具名"},
                "args": {"type": "string", "description": "参数"},
            },
            "required": ["tool", "args"]
        }),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "binary_tools_path":
        path = f"{THIRDPARTY}/binary_tools/"
        return [TextContent(type="text", text=f"二进制工具目录: {path}\n包含: 各类二进制分析脚本")]

    elif name == "binary_analysis":
        script_path = f"{THIRDPARTY}/binary_tools/{arguments['tool']}.py"
        if not os.path.exists(script_path):
            return [TextContent(type="text", text=f"工具不存在: {script_path}")]
        cmd = f"python {script_path} {arguments['args']}"
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            result = {"return_code": proc.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")}
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())