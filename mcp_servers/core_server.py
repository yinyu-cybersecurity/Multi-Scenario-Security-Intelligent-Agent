# mcp_servers/core_server.py
"""核心工具MCP服务器 - http_request, bash"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx
import asyncio
import json

server = Server("ctf-core")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="http_request",
            description="发送HTTP请求获取目标URL内容",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标URL"},
                    "method": {"type": "string", "default": "GET", "description": "HTTP方法"},
                    "headers": {"type": "object", "description": "请求头"},
                    "data": {"type": "string", "description": "请求体"},
                    "timeout": {"type": "integer", "default": 30, "description": "超时秒数"},
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="bash",
            description="执行系统命令",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "命令"},
                    "timeout": {"type": "integer", "default": 120, "description": "超时秒数"},
                },
                "required": ["command"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "http_request": handle_http_request,
        "bash": handle_bash,
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def handle_http_request(args: dict):
    url = args["url"]
    method = args.get("method", "GET").upper()
    headers = args.get("headers", {})
    data = args.get("data")
    timeout = args.get("timeout", 30)

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "POST":
                resp = await client.post(url, headers=headers, data=data)
            elif method == "PUT":
                resp = await client.put(url, headers=headers, data=data)
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                return [TextContent(type="text", text=f"Unsupported method: {method}")]

            result = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.text[:50000]
            }
            if "flag{" in resp.text.lower() or "ctf{" in resp.text.lower():
                result["flag_detected"] = True
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def handle_bash(args: dict):
    command = args["command"]
    timeout = args.get("timeout", 120)

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
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
        await proc.wait()
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