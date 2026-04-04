# mcp_servers/web_advanced_server.py
"""Web高级工具MCP服务器 - dirsearch, jwt_tool, gopherus, ssrfmap, xxeinjector, jsfinder, githacker, ghostcat"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-web-advanced")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="dirsearch", description="Web目录扫描", inputSchema={"type": "object", "properties": {"url": {"type": "string"}, "timeout": {"type": "integer", "default": 300}}, "required": ["url"]}),
        Tool(name="jwt_tool", description="JWT安全测试", inputSchema={"type": "object", "properties": {"token": {"type": "string"}, "action": {"type": "string", "default": "decode"}}, "required": ["token"]}),
        Tool(name="gopherus", description="Gopher SSRF利用", inputSchema={"type": "object", "properties": {"type": {"type": "string", "description": "类型: mysql/redis/fastcgi/smtp"}, "host": {"type": "string"}, "port": {"type": "integer", "default": 3306}}, "required": ["type", "host"]}),
        Tool(name="ssrfmap", description="SSRF攻击工具", inputSchema={"type": "object", "properties": {"url": {"type": "string"}, "module": {"type": "string", "default": "redis"}}, "required": ["url"]}),
        Tool(name="xxeinjector", description="XXE注入工具", inputSchema={"type": "object", "properties": {"file": {"type": "string"}, "url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="jsfinder", description="JS文件发现", inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="githacker", description="Git泄露利用", inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
        Tool(name="ghostcat", description="Tomcat Ghostcat漏洞", inputSchema={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "dirsearch": lambda a: run_python_tool("dirsearch/dirsearch.py", f"-u {a['url']}", a.get("timeout", 300)),
        "jwt_tool": lambda a: run_python_tool("jwt_tool/jwt_tool.py", f"{a['token']} -M {a.get('action', 'decode')}", 60),
        "gopherus": lambda a: run_python_tool("gopherus/gopherus.py", f"--{a['type']} {a['host']} {a.get('port', 3306)}", 60),
        "ssrfmap": lambda a: run_python_tool("ssrfmap/ssrfmap.py", f"-r {a['url']} -m {a.get('module', 'redis')}", 300),
        "xxeinjector": lambda a: run_python_tool("xxeinjector/xxeinjector.py", f"-u {a['url']} -f {a.get('file', '')}", 300),
        "jsfinder": lambda a: run_python_tool("jsfinder/JSFinder.py", f"-u {a['url']}", 120),
        "githacker": lambda a: run_python_tool("githacker/GitHacker.py", f"-u {a['url']}", 300),
        "ghostcat": lambda a: run_python_tool("ghostcat/ghostcat.py", f"-u {a['url']}", 60),
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def run_python_tool(script_path: str, args: str, timeout: int):
    cmd = f"python {THIRDPARTY}/{script_path} {args}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        result = {"return_code": proc.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")}
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except asyncio.TimeoutError:
        proc.kill()
        return [TextContent(type="text", text=f"Timeout after {timeout}s")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())