# mcp_servers/ai_server.py
"""AI安全工具MCP服务器 - ai_probe"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx
import json

server = Server("ctf-ai")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="ai_probe",
            description="AI模型探测和Prompt Injection测试",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标URL"},
                    "prompt": {"type": "string", "description": "测试prompt"},
                },
                "required": ["target"]
            }
        ),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "ai_probe":
        return await handle_ai_probe(arguments)
    return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def handle_ai_probe(args: dict):
    target = args["target"]
    prompt = args.get("prompt", "Hello")

    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            endpoints = ["/v1/chat/completions", "/api/chat", "/api/generate"]
            results = []
            for endpoint in endpoints:
                try:
                    resp = await client.post(
                        f"{target}{endpoint}",
                        json={"prompt": prompt, "message": prompt},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        results.append({"endpoint": endpoint, "status": "accessible", "response": resp.text[:500]})
                except:
                    pass
            return [TextContent(type="text", text=json.dumps(results, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())