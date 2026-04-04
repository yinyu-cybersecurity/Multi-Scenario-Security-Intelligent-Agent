# mcp_servers/recon_server.py
"""信息收集工具MCP服务器 - nmap, nuclei"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import shutil
import json

server = Server("ctf-recon")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="nmap",
            description="端口扫描",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {"type": "string", "description": "nmap参数"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["args"]
            }
        ),
        Tool(
            name="nuclei",
            description="漏洞模板扫描",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {"type": "string", "description": "nuclei参数"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["args"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    tool_path = shutil.which(name)
    if not tool_path:
        return [TextContent(type="text", text=f"工具未安装: {name}")]

    cmd = f"{tool_path} {arguments['args']}"
    timeout = arguments.get("timeout", 300)

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