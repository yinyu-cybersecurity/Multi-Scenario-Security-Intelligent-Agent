# mcp_servers/deserialization_server.py
"""反序列化工具MCP服务器 - ysoserial, marshalsec, phpggc, php_filter_chain_generator"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import os
import json

server = Server("ctf-deserialization")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="ysoserial", description="Java反序列化payload生成", inputSchema={
            "type": "object",
            "properties": {
                "gadget": {"type": "string", "description": "gadget链名"},
                "command": {"type": "string", "description": "要执行的命令"},
            },
            "required": ["gadget", "command"]
        }),
        Tool(name="marshalsec", description="Java反序列化利用", inputSchema={
            "type": "object",
            "properties": {
                "gadget": {"type": "string", "description": "gadget类型"},
            },
            "required": ["gadget"]
        }),
        Tool(name="phpggc", description="PHP反序列化payload生成", inputSchema={
            "type": "object",
            "properties": {
                "gadget": {"type": "string", "description": "gadget链名"},
                "parameters": {"type": "string", "description": "参数"},
            },
            "required": ["gadget"]
        }),
        Tool(name="php_filter_chain", description="PHP Filter链生成器", inputSchema={
            "type": "object",
            "properties": {
                "chain": {"type": "string", "description": "要生成的字符串"},
            },
            "required": ["chain"]
        }),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "ysoserial": handle_ysoserial,
        "marshalsec": handle_marshalsec,
        "phpggc": handle_phpggc,
        "php_filter_chain": handle_php_filter_chain,
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def handle_ysoserial(args: dict):
    jar_path = f"{THIRDPARTY}/ysoserial/ysoserial.jar"
    if not os.path.exists(jar_path):
        return [TextContent(type="text", text=f"工具不存在: {jar_path}")]
    cmd = f"java -jar {jar_path} {args['gadget']} \"{args['command']}\""
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return [TextContent(type="text", text=stdout.decode("utf-8", errors="replace"))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def handle_marshalsec(args: dict):
    jar_path = f"{THIRDPARTY}/marshalsec/marshalsec.jar"
    if not os.path.exists(jar_path):
        return [TextContent(type="text", text=f"工具不存在: {jar_path}")]
    cmd = f"java -cp {jar_path} marshalsec.{args['gadget']}"
    return [TextContent(type="text", text=f"命令: {cmd}")]

async def handle_phpggc(args: dict):
    script_path = f"{THIRDPARTY}/phpggc/phpggc"
    if not os.path.exists(script_path):
        return [TextContent(type="text", text=f"工具不存在: {script_path}")]
    params = args.get("parameters", "")
    cmd = f"php {script_path} {args['gadget']} {params}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return [TextContent(type="text", text=stdout.decode("utf-8", errors="replace"))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def handle_php_filter_chain(args: dict):
    script_path = f"{THIRDPARTY}/php_filter_chain_generator/generate.py"
    if not os.path.exists(script_path):
        return [TextContent(type="text", text=f"工具不存在: {script_path}")]
    cmd = f"php {script_path} {args['chain']}"
    try:
        proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        return [TextContent(type="text", text=stdout.decode("utf-8", errors="replace"))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())