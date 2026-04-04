# mcp_servers/ad_server.py
"""AD域渗透工具MCP服务器 - bloodhound, petitpotam, rubeus"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-ad")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="bloodhound_path", description="获取BloodHound工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="petitpotam", description="AD认证攻击", inputSchema={"type": "object", "properties": {"target": {"type": "string"}, "listener": {"type": "string"}}, "required": ["target", "listener"]}),
        Tool(name="rubeus_path", description="获取Rubeus工具路径", inputSchema={"type": "object", "properties": {}}),
        Tool(name="rubeus_command", description="生成Rubeus命令", inputSchema={"type": "object", "properties": {"action": {"type": "string", "description": "动作: asktgt/asktgs/s4u/dump"}}}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "bloodhound_path":
        return [TextContent(type="text", text=f"BloodHound路径: {THIRDPARTY}/bloodhound/BloodHound.exe\n使用方式: 运行GUI进行AD关系分析")]

    elif name == "petitpotam":
        return await run_petitpotam(arguments)

    elif name == "rubeus_path":
        return [TextContent(type="text", text=f"Rubeus路径: {THIRDPARTY}/rubeus/Rubeus.exe\n使用方式: 上传到目标机器后执行")]

    elif name == "rubeus_command":
        action = arguments.get("action", "dump")
        cmd = f"Rubeus.exe {action}"
        return [TextContent(type="text", text=f"Rubeus命令: {cmd}")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def run_petitpotam(args: dict):
    script_path = f"{THIRDPARTY}/petitpotam/PetitPotam.py"
    if not os.path.exists(script_path):
        return [TextContent(type="text", text=f"工具不存在: {script_path}")]

    cmd = f"python {script_path} {args['target']} {args['listener']}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
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