# mcp_servers/recon_advanced_server.py
"""信息收集高级工具MCP服务器 - subfinder, whatweb, xray"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import shutil
import os
import json

server = Server("ctf-recon-advanced")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="subfinder", description="子域名发现", inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}),
        Tool(name="whatweb", description="Web指纹识别", inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="xray", description="被动扫描代理", inputSchema={"type": "object", "properties": {"url": {"type": "string"}, "mode": {"type": "string", "default": "webscan"}}, "required": ["url"]}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "subfinder": lambda a: run_go_tool("subfinder", f"-d {a['domain']}"),
        "whatweb": lambda a: run_tool(f"{THIRDPARTY}/whatweb/whatweb", a['url']),
        "xray": lambda a: run_tool(f"{THIRDPARTY}/xray/xray", f"{a.get('mode', 'webscan')} --url {a['url']}"),
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def run_go_tool(name: str, args: str):
    path = shutil.which(name) or f"{THIRDPARTY}/{name}/{name}"
    if not os.path.exists(path) and not shutil.which(name):
        return [TextContent(type="text", text=f"工具未安装: {name}")]
    cmd = f"{path} {args}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        result = {"return_code": proc.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")}
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def run_tool(path: str, args: str):
    if not os.path.exists(path):
        return [TextContent(type="text", text=f"工具不存在: {path}")]
    cmd = f"{path} {args}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        result = {"return_code": proc.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")}
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())