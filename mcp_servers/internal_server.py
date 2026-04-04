# mcp_servers/internal_server.py
"""内网工具MCP服务器 - fscan"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-internal")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="fscan",
            description="内网综合扫描",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {"type": "string", "description": "fscan参数"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["args"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "fscan":
        return await run_fscan(arguments)
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def run_fscan(args: dict):
    # 检测操作系统选择正确的fscan
    import platform
    if platform.system() == "Windows":
        fscan_path = f"{THIRDPARTY}/fscan_windows/fscan.exe"
    else:
        fscan_path = f"{THIRDPARTY}/fscan_linux/fscan"

    if not os.path.exists(fscan_path):
        fscan_path = "fscan"  # 尝试系统PATH

    cmd = f"{fscan_path} {args['args']}"
    timeout = args.get("timeout", 300)

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