# mcp_servers/web_server.py
"""Web工具MCP服务器 - sqlmap, ffuf"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import shutil
import json

server = Server("ctf-web")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="sqlmap",
            description="SQL注入自动化利用",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {"type": "string", "description": "sqlmap参数"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["args"]
            }
        ),
        Tool(
            name="ffuf",
            description="目录/参数爆破",
            inputSchema={
                "type": "object",
                "properties": {
                    "args": {"type": "string", "description": "ffuf参数"},
                    "timeout": {"type": "integer", "default": 300},
                },
                "required": ["args"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {"sqlmap": run_tool, "ffuf": run_tool}
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(name, arguments)

async def run_tool(tool_name: str, args: dict):
    tool_path = shutil.which(tool_name)
    if not tool_path:
        # 尝试thirdparty目录
        import os
        tp_path = f"thirdparty/{tool_name}/{tool_name}.py"
        if os.path.exists(tp_path):
            cmd = f"python {tp_path} {args['args']}"
        else:
            return [TextContent(type="text", text=f"工具未安装: {tool_name}")]
    else:
        cmd = f"{tool_path} {args['args']}"

    timeout = args.get("timeout", 300)
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        result = {
            "return_code": proc.returncode,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace")
        }
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