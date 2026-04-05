#!/usr/bin/env python3
"""
Kali MCP Server - 极简基础能力 + 比赛适配 + 技能系统

遵循Claude Code最佳实践：
- 框架只做执行管道
- AI自己决定用什么工具、怎么用
- 不限制AI的命令构造能力

提供能力：
1. bash - 执行任意命令（可调用Kali 300+工具）
2. http - HTTP请求
3. read/write - 文件操作
4. remember/recall - 记忆存储
5. 比赛工具 - list/start/stop/submit
6. 技能系统 - search_skills
"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import httpx
import json
import os
from pathlib import Path

server = Server("kali")

# === 比赛平台配置（从环境变量读取）===
COMPETITION_HOST = os.environ.get("COMPETITION_SERVER_HOST", "")
COMPETITION_TOKEN = os.environ.get("COMPETITION_AGENT_TOKEN", "")

# === 工具定义 ===

@server.list_tools()
async def list_tools():
    return [
        # ===== 基础能力 =====

        # 1. Bash执行 - AI可以执行任意命令
        Tool(
            name="bash",
            description="执行任意bash命令，可调用Kali系统的任何工具（nmap/sqlmap/ffuf/hashcat等300+工具）",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的命令，如: nmap -sV target"},
                    "timeout": {"type": "integer", "default": 300, "description": "超时秒数"}
                },
                "required": ["command"]
            }
        ),

        # 2. HTTP请求
        Tool(
            name="http",
            description="发送HTTP请求，支持自定义method/headers/body",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "请求URL"},
                    "method": {"type": "string", "default": "GET", "description": "HTTP方法"},
                    "headers": {"type": "object", "default": {}, "description": "请求头"},
                    "body": {"type": "string", "default": "", "description": "请求体"},
                    "timeout": {"type": "integer", "default": 30, "description": "超时秒数"}
                },
                "required": ["url"]
            }
        ),

        # 3. 读文件
        Tool(
            name="read",
            description="读取文件内容",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "文件路径"}},
                "required": ["path"]
            }
        ),

        # 4. 写文件
        Tool(
            name="write",
            description="写入文件，可用来保存payload/脚本/结果",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "文件路径"},
                    "content": {"type": "string", "description": "文件内容"}
                },
                "required": ["path", "content"]
            }
        ),

        # 5. 记忆存储
        Tool(
            name="remember",
            description="存储关键信息供后续使用（如发现的端点、凭证、提示等）",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "记忆关键词"},
                    "value": {"type": "string", "description": "记忆内容"}
                },
                "required": ["key", "value"]
            }
        ),

        # 6. 记忆检索
        Tool(
            name="recall",
            description="检索之前存储的记忆",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string", "description": "检索关键词"}},
                "required": ["query"]
            }
        ),

        # ===== 比赛工具 =====

        Tool(
            name="list_challenges",
            description="获取比赛题目列表",
            inputSchema={"type": "object", "properties": {}}
        ),

        Tool(
            name="start_challenge",
            description="启动指定题目的容器实例",
            inputSchema={
                "type": "object",
                "properties": {"code": {"type": "string", "description": "题目代码"}},
                "required": ["code"]
            }
        ),

        Tool(
            name="stop_challenge",
            description="停止指定题目的容器实例",
            inputSchema={
                "type": "object",
                "properties": {"code": {"type": "string", "description": "题目代码"}},
                "required": ["code"]
            }
        ),

        Tool(
            name="submit_flag",
            description="提交FLAG答案",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "题目代码"},
                    "flag": {"type": "string", "description": "FLAG内容"}
                },
                "required": ["code", "flag"]
            }
        ),

        Tool(
            name="view_hint",
            description="查看题目提示（会扣分）",
            inputSchema={
                "type": "object",
                "properties": {"code": {"type": "string", "description": "题目代码"}},
                "required": ["code"]
            }
        ),

        # ===== 技能系统 =====

        Tool(
            name="search_skills",
            description="搜索相关攻击技能",
            inputSchema={
                "type": "object",
                "properties": {"query": {"type": "string", "description": "技能关键词，如: sqli, xss, rce"}},
                "required": ["query"]
            }
        ),
    ]

# === 工具调度 ===

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    # 基础能力
    if name == "bash":
        return await exec_bash(arguments["command"], arguments.get("timeout", 300))
    elif name == "http":
        return await http_request(arguments)
    elif name == "read":
        return await read_file(arguments["path"])
    elif name == "write":
        return await write_file(arguments["path"], arguments["content"])
    elif name == "remember":
        return await store_memory(arguments["key"], arguments["value"])
    elif name == "recall":
        return await retrieve_memory(arguments["query"])

    # 比赛工具
    elif name == "list_challenges":
        return await competition_api("GET", "/api/challenges")
    elif name == "start_challenge":
        return await competition_api("POST", "/api/start_challenge", {"code": arguments["code"]})
    elif name == "stop_challenge":
        return await competition_api("POST", "/api/stop_challenge", {"code": arguments["code"]})
    elif name == "submit_flag":
        return await competition_api("POST", "/api/submit", {"code": arguments["code"], "flag": arguments["flag"]})
    elif name == "view_hint":
        return await competition_api("POST", "/api/hint", {"code": arguments["code"]})

    # 技能系统
    elif name == "search_skills":
        return await search_skills_handler(arguments["query"])

    return [TextContent(type="text", text=f"Unknown tool: {name}")]

# === 基础能力实现 ===

async def exec_bash(command: str, timeout: int):
    """执行bash命令 - AI可以调用任何Kali工具"""
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
            "stderr": stderr.decode("utf-8", errors="replace"),
            "command": command
        }
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except asyncio.TimeoutError:
        proc.kill()
        return [TextContent(type="text", text=f"Timeout after {timeout}s")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def http_request(args: dict):
    """HTTP请求"""
    try:
        timeout = args.get("timeout", 30)
        async with httpx.AsyncClient(timeout=timeout) as client:
            method = args.get("method", "GET").upper()
            url = args["url"]
            headers = args.get("headers", {})
            body = args.get("body", "")

            if method == "GET":
                resp = await client.get(url, headers=headers)
            elif method == "POST":
                resp = await client.post(url, headers=headers, content=body)
            else:
                resp = await client.request(method, url, headers=headers, content=body)

            result = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "content": resp.text[:10000]
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def read_file(path: str):
    """读文件"""
    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
        return [TextContent(type="text", text=content[:50000])]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def write_file(path: str, content: str):
    """写文件"""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content, encoding="utf-8")
        return [TextContent(type="text", text=f"Written {len(content)} bytes to {path}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

# === 内存存储 ===
# 使用相对路径，跨平台兼容
PROJECT_ROOT = Path(__file__).parent.parent
MEMORY_FILE = str(PROJECT_ROOT / "logs" / "memory.json")
memory_store = {}

def _load_memory():
    global memory_store
    try:
        if os.path.exists(MEMORY_FILE):
            memory_store = json.loads(Path(MEMORY_FILE).read_text())
    except:
        memory_store = {}

def _save_memory():
    try:
        Path(MEMORY_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(MEMORY_FILE).write_text(json.dumps(memory_store, indent=2, ensure_ascii=False))
    except:
        pass

async def store_memory(key: str, value: str):
    _load_memory()
    memory_store[key] = value
    _save_memory()
    return [TextContent(type="text", text=f"✓ Remembered: {key}")]

async def retrieve_memory(query: str):
    _load_memory()
    results = {k: v for k, v in memory_store.items() if query.lower() in k.lower() or query.lower() in str(v).lower()}
    if not results:
        return [TextContent(type="text", text=f"No memory found for: {query}")]
    return [TextContent(type="text", text=json.dumps(results, indent=2, ensure_ascii=False))]

# === 比赛平台API ===

async def competition_api(method: str, endpoint: str, data: dict = None):
    """比赛平台API调用"""
    if not COMPETITION_HOST or not COMPETITION_TOKEN:
        return [TextContent(type="text", text="比赛平台未配置，请设置 COMPETITION_SERVER_HOST 和 COMPETITION_AGENT_TOKEN 环境变量")]

    try:
        url = f"http://{COMPETITION_HOST}{endpoint}"
        headers = {"Agent-Token": COMPETITION_TOKEN, "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=30) as client:
            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                resp = await client.post(url, headers=headers, json=data or {})

            result = resp.json()
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

# === 技能系统 ===

async def search_skills_handler(query: str):
    """搜索技能"""
    # 使用相对路径，跨平台兼容
    skills_dir = PROJECT_ROOT / "skills"
    if not skills_dir.exists():
        return [TextContent(type="text", text="技能目录不存在")]

    results = []
    query_lower = query.lower()

    for skill_file in skills_dir.glob("*.yaml"):
        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace").lower()
            if query_lower in content or query_lower in skill_file.stem.lower():
                results.append({
                    "name": skill_file.stem,
                    "file": str(skill_file.name)
                })
        except:
            continue

    if not results:
        return [TextContent(type="text", text=f"未找到相关技能: {query}")]

    return [TextContent(type="text", text=json.dumps(results, indent=2, ensure_ascii=False))]

# === MCP启动 ===
if __name__ == "__main__":
    from mcp.server.stdio import stdio_server
    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    asyncio.run(main())