# mcp_servers/competition_server.py
"""比赛平台工具MCP服务器 - list/start/stop/submit/view"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx
import os
import json

server = Server("ctf-competition")

SERVER_HOST = os.environ.get("COMPETITION_SERVER_HOST", "")
AGENT_TOKEN = os.environ.get("COMPETITION_AGENT_TOKEN", "")

@server.list_tools()
async def list_tools():
    return [
        Tool(name="list_challenges", description="获取当前可用的赛题列表", inputSchema={"type": "object", "properties": {}}),
        Tool(name="start_challenge", description="启动指定赛题的容器实例", inputSchema={"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}),
        Tool(name="stop_challenge", description="停止指定赛题的容器实例", inputSchema={"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}),
        Tool(name="submit_flag", description="提交赛题的Flag答案", inputSchema={"type": "object", "properties": {"code": {"type": "string"}, "flag": {"type": "string"}}, "required": ["code", "flag"]}),
        Tool(name="view_hint", description="查看赛题提示（会扣分）", inputSchema={"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "list_challenges": handle_list_challenges,
        "start_challenge": handle_start_challenge,
        "stop_challenge": handle_stop_challenge,
        "submit_flag": handle_submit_flag,
        "view_hint": handle_view_hint,
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def api_call(method: str, endpoint: str, data: dict = None):
    if not SERVER_HOST or not AGENT_TOKEN:
        return {"code": -1, "message": "平台未配置SERVER_HOST或AGENT_TOKEN"}
    url = f"http://{SERVER_HOST}{endpoint}"
    headers = {"Agent-Token": AGENT_TOKEN, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            resp = await client.get(url, headers=headers)
        else:
            resp = await client.post(url, headers=headers, json=data or {})
        return resp.json()

async def handle_list_challenges(args: dict):
    result = await api_call("GET", "/api/challenges")
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

async def handle_start_challenge(args: dict):
    result = await api_call("POST", "/api/challenge/start", {"code": args["code"]})
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

async def handle_stop_challenge(args: dict):
    result = await api_call("POST", "/api/challenge/stop", {"code": args["code"]})
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

async def handle_submit_flag(args: dict):
    result = await api_call("POST", "/api/challenge/submit", {"code": args["code"], "flag": args["flag"]})
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

async def handle_view_hint(args: dict):
    result = await api_call("GET", f"/api/challenge/hint/{args['code']}")
    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())