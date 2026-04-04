# mcp_servers/oa_server.py
"""OA漏洞工具MCP服务器 - oa_tools"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-oa")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="oa_tools_path", description="获取OA漏洞工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="oa_exploit", description="OA漏洞利用", inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标URL"},
                "exploit": {"type": "string", "description": "漏洞类型/脚本名"},
            },
            "required": ["target", "exploit"]
        }),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "oa_tools_path":
        path = f"{THIRDPARTY}/oa_tools/"
        return [TextContent(type="text", text=f"OA漏洞工具目录: {path}\n使用方式: python {path}/<exploit>.py <target>")]

    elif name == "oa_exploit":
        script_path = f"{THIRDPARTY}/oa_tools/{arguments['exploit']}.py"
        if not os.path.exists(script_path):
            return [TextContent(type="text", text=f"漏洞脚本不存在: {script_path}")]
        cmd = f"python {script_path} {arguments['target']}"
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