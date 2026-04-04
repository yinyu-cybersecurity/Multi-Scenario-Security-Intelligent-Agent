# mcp_servers/jndi_server.py
"""JNDI注入工具MCP服务器 - jndiexploit"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-jndi")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="jndiexploit", description="JNDI注入利用", inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "监听IP"},
                "command": {"type": "string", "description": "要执行的命令"},
            },
            "required": ["ip"]
        }),
        Tool(name="jndiexploit_path", description="获取JNDIExploit工具路径", inputSchema={"type": "object", "properties": {}}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "jndiexploit":
        jar_path = f"{THIRDPARTY}/jndiexploit/JNDIExploit.jar"
        if not os.path.exists(jar_path):
            return [TextContent(type="text", text=f"工具不存在: {jar_path}")]
        cmd = f"java -jar {jar_path} -i {arguments['ip']}"
        if "command" in arguments:
            cmd += f" -c \"{arguments['command']}\""
        try:
            proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            result = {"return_code": proc.returncode, "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")}
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "jndiexploit_path":
        path = f"{THIRDPARTY}/jndiexploit/JNDIExploit.jar"
        return [TextContent(type="text", text=f"JNDIExploit路径: {path}\n使用方式: java -jar {path} -i <ip> -c <command>")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())