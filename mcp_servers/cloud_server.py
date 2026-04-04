# mcp_servers/cloud_server.py
"""云安全工具MCP服务器 - cloud_storage_check, cloud_metadata, cloud_tools"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import httpx
import asyncio
import os
import json

server = Server("ctf-cloud")
THIRDPARTY = "thirdparty"

@server.list_tools()
async def list_tools():
    return [
        Tool(name="cloud_storage_check", description="云存储桶检测", inputSchema={
            "type": "object",
            "properties": {"bucket_url": {"type": "string"}},
            "required": ["bucket_url"]
        }),
        Tool(name="cloud_metadata", description="云环境元数据获取", inputSchema={"type": "object", "properties": {}}),
        Tool(name="cloud_tools_path", description="获取云安全工具路径", inputSchema={"type": "object", "properties": {}}),
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "cloud_storage_check": handle_cloud_storage_check,
        "cloud_metadata": handle_cloud_metadata,
        "cloud_tools_path": handle_cloud_tools_path,
    }
    handler = handlers.get(name)
    if not handler:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    return await handler(arguments)

async def handle_cloud_storage_check(args: dict):
    bucket_url = args["bucket_url"]
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.get(bucket_url)
            result = {"status_code": resp.status_code, "accessible": resp.status_code == 200, "content": resp.text[:5000]}
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def handle_cloud_metadata(args: dict):
    metadata_urls = {
        "aws": "http://169.254.169.254/latest/meta-data/",
        "gcp": "http://metadata.google.internal/computeMetadata/v1/",
        "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    }
    results = {}
    async with httpx.AsyncClient(timeout=5, verify=False) as client:
        for provider, url in metadata_urls.items():
            try:
                headers = {"Metadata-Flavor": "Google"} if provider == "gcp" else {}
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    results[provider] = resp.text[:1000]
            except:
                pass
    return [TextContent(type="text", text=json.dumps(results, indent=2, ensure_ascii=False))]

async def handle_cloud_tools_path(args: dict):
    path = f"{THIRDPARTY}/cloud_tools/"
    return [TextContent(type="text", text=f"云安全工具目录: {path}\n使用方式: 根据具体需求调用对应脚本")]

if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())