#!/usr/bin/env python3
"""
Kali MCP Server - 企业级标准

对齐 Claude Code 最佳实践:
- 框架只做执行管道，AI 完全自主决策
- bash 输出智能截断（防止 LLM 上下文溢出）
- 比赛 API 严格对齐官方文档
- 技能搜索返回完整知识内容
- 记忆系统带时间戳和分类

提供能力:
1. bash      - 执行任意命令（Kali 300+ 工具）
2. http      - HTTP 请求
3. read/write - 文件操作
4. remember/recall - 结构化记忆
5. 比赛工具  - list/start/stop/submit/hint（严格对齐官方API）
6. search_skills / read_skill - 技能系统
"""

from mcp.server import Server
from mcp.types import Tool, TextContent
import asyncio
import httpx
import json
import math
import signal
import os
import re
import time
import yaml
from collections import Counter
from pathlib import Path
from datetime import datetime

# OpenSpace 集成
try:
    from app.tools_v2.skill_engine import get_skill_engine, initialize_skill_engine
    SKILL_ENGINE_AVAILABLE = True
except ImportError:
    SKILL_ENGINE_AVAILABLE = False

server = Server("kali")

# === 全局配置 ===
PROJECT_ROOT = Path(__file__).parent.parent
COMPETITION_HOST = os.environ.get("COMPETITION_SERVER_HOST", "")
COMPETITION_TOKEN = os.environ.get("COMPETITION_AGENT_TOKEN", "")

# HTTP 连接池复用（全局客户端，懒初始化）
_http_client: httpx.AsyncClient | None = None


async def _get_http_client(timeout: int = 30, follow_redirects: bool = True) -> httpx.AsyncClient:
    """获取或创建全局 HTTP 客户端（连接池复用）"""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,  # CTF 场景常有自签名证书
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )
    return _http_client

# bash 输出限制
BASH_OUTPUT_MAX_CHARS = 15000  # 单次 bash 输出最大字符数
BASH_OUTPUT_HEAD_CHARS = 6000  # 截断时保留头部
BASH_OUTPUT_TAIL_CHARS = 6000  # 截断时保留尾部

# 比赛 API 限频（异步锁保护，防止竞态条件）
_last_api_call_time = 0.0
API_RATE_LIMIT_INTERVAL = 0.35  # 秒
_api_rate_lock = asyncio.Lock()  # 异步锁保护并发访问


# ============================================================================
# 工具定义
# ============================================================================

@server.list_tools()
async def list_tools():
    tools = [
        # === 基础能力 ===
        Tool(
            name="bash",
            description=(
                "Execute any bash command. Full access to Kali Linux 300+ security tools "
                "(nmap, sqlmap, ffuf, hashcat, hydra, gobuster, nuclei, crackmapexec, etc). "
                "Output is auto-truncated if too long."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command to execute"},
                    "timeout": {"type": "integer", "default": 300, "description": "Timeout in seconds"},
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="http",
            description="Send HTTP request with custom method/headers/body. Supports GET/POST/PUT/DELETE/PATCH/OPTIONS.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Request URL"},
                    "method": {"type": "string", "default": "GET", "description": "HTTP method"},
                    "headers": {"type": "object", "default": {}, "description": "Request headers"},
                    "body": {"type": "string", "default": "", "description": "Request body"},
                    "timeout": {"type": "integer", "default": 30, "description": "Timeout in seconds"},
                    "follow_redirects": {"type": "boolean", "default": True, "description": "Follow redirects"},
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="read",
            description="Read file content. Supports text files and binary file hex dump.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "max_size": {"type": "integer", "default": 50000, "description": "Max chars to read"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="write",
            description="Write content to file. Creates parent directories automatically.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "File content"},
                },
                "required": ["path", "content"],
            },
        ),

        # === 记忆系统 ===
        Tool(
            name="remember",
            description=(
                "Store key information for later use. Use for: endpoints, credentials, "
                "tech stack, vulnerabilities, bypass methods, attack progress."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Memory key (e.g. 'admin_cred', 'sqli_endpoint')"},
                    "value": {"type": "string", "description": "Memory content"},
                    "category": {
                        "type": "string",
                        "default": "general",
                        "description": "Category: endpoint, credential, vuln, tech_stack, progress, general",
                    },
                },
                "required": ["key", "value"],
            },
        ),
        Tool(
            name="recall",
            description="Search stored memories. Returns all matching entries with timestamps.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search keyword (matches key, value, and category)"},
                },
                "required": ["query"],
            },
        ),

        # === 技能系统 ===
        Tool(
            name="search_skills",
            description=(
                "Search the attack knowledge base. Returns skill names and summaries. "
                "Use when encountering unfamiliar vulnerability types or bypass techniques."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search keyword (e.g. sqli, xss, rce, ssrf, ssti, jwt)"},
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="read_skill",
            description="Read full content of a specific skill file for detailed attack knowledge.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Skill file name (without .yaml extension)"},
                },
                "required": ["name"],
            },
        ),

        # === OpenSpace 技能管理 ===
        Tool(
            name="create_skill",
            description="Create a new skill file to record attack techniques or experiences.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Skill name (e.g. 'cloud_aws', 'sqli_waf_bypass')"},
                    "content": {"type": "string", "description": "Skill content in YAML format"},
                },
                "required": ["name", "content"],
            },
        ),
        Tool(
            name="update_skill",
            description="Update an existing skill file with new information.",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Skill name to update"},
                    "content": {"type": "string", "description": "New content to append or merge"},
                },
                "required": ["name", "content"],
            },
        ),
        Tool(
            name="list_skills",
            description="List all available skill files in the knowledge base.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]

    # === 比赛工具（仅在比赛模式下注册）===
    if COMPETITION_HOST and COMPETITION_TOKEN:
        tools.extend([
            Tool(
                name="list_challenges",
                description=(
                    "Get competition challenge list. Shows: title, code, difficulty, level, score, "
                    "flag progress, instance status, entrypoint. Use this FIRST to plan your attack order."
                ),
                inputSchema={"type": "object", "properties": {}},
            ),
            Tool(
                name="start_challenge",
                description=(
                    "Start a challenge instance. Returns entrypoint address(es). "
                    "Max 3 concurrent instances. Must stop others if limit reached."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Challenge code from list_challenges"},
                    },
                    "required": ["code"],
                },
            ),
            Tool(
                name="stop_challenge",
                description="Stop a running challenge instance to free resources.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Challenge code"},
                    },
                    "required": ["code"],
                },
            ),
            Tool(
                name="submit_flag",
                description=(
                    "Submit a FLAG answer. Instance must be running. "
                    "Supports multiple flags per challenge. Each flag scores only once. "
                    "Response tells you if correct and progress (e.g. 1/2 flags)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Challenge code"},
                        "flag": {"type": "string", "description": "The FLAG value (format: flag{...})"},
                    },
                    "required": ["code", "flag"],
                },
            ),
            Tool(
                name="view_hint",
                description=(
                    "View challenge hint. WARNING: costs 10% score penalty! "
                    "Only use as last resort after exhausting other approaches."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Challenge code"},
                    },
                    "required": ["code"],
                },
            ),
        ])

    return tools


# ============================================================================
# 工具调度
# ============================================================================

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    handlers = {
        "bash": lambda: exec_bash(arguments.get("command", ""), arguments.get("timeout", 300)),
        "http": lambda: http_request(arguments),
        "read": lambda: read_file(arguments.get("path", ""), arguments.get("max_size", 50000)),
        "write": lambda: write_file(arguments.get("path", ""), arguments.get("content", "")),
        "remember": lambda: store_memory(
            arguments.get("key", ""),
            arguments.get("value", ""),
            arguments.get("category", "general"),
        ),
        "recall": lambda: retrieve_memory(arguments.get("query", "")),
        "search_skills": lambda: search_skills_handler(arguments.get("query", "")),
        "read_skill": lambda: read_skill_handler(arguments.get("name", "")),
        # OpenSpace 技能管理
        "create_skill": lambda: create_skill_handler(
            arguments.get("name", ""),
            arguments.get("content", ""),
        ),
        "update_skill": lambda: update_skill_handler(
            arguments.get("name", ""),
            arguments.get("content", ""),
        ),
        "list_skills": lambda: list_skills_handler(),
        # 比赛工具 - 严格对齐官方 API 文档
        "list_challenges": lambda: competition_api("GET", "/api/challenges"),
        "start_challenge": lambda: _start_challenge_with_reset(arguments.get("code", "")),
        "stop_challenge": lambda: competition_api(
            "POST", "/api/stop_challenge", {"code": arguments.get("code", "")}
        ),
        "submit_flag": lambda: competition_api(
            "POST", "/api/submit",
            {"code": arguments.get("code", ""), "flag": arguments.get("flag", "")},
        ),
        "view_hint": lambda: competition_api(
            "POST", "/api/hint", {"code": arguments.get("code", "")}
        ),
    }

    handler = handlers.get(name)
    if handler:
        result = handler()
        if asyncio.iscoroutine(result):
            return await result
        return result
    return [TextContent(type="text", text=f"Unknown tool: {name}")]


# ============================================================================
# 基础能力实现
# ============================================================================

def _truncate_output(text: str, max_chars: int = BASH_OUTPUT_MAX_CHARS) -> str:
    """智能截断长输出，保留头尾"""
    if len(text) <= max_chars:
        return text
    return (
        text[:BASH_OUTPUT_HEAD_CHARS]
        + f"\n\n... [OUTPUT TRUNCATED: {len(text)} total chars, showing first {BASH_OUTPUT_HEAD_CHARS} and last {BASH_OUTPUT_TAIL_CHARS}] ...\n\n"
        + text[-BASH_OUTPUT_TAIL_CHARS:]
    )


async def exec_bash(command: str, timeout: int):
    """执行 bash 命令 - AI 可调用任何 Kali 工具"""
    if not command:
        return [TextContent(type="text", text="Error: empty command")]

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # New process group for clean timeout kills
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        stdout_str = _truncate_output(stdout.decode("utf-8", errors="replace"))
        stderr_str = _truncate_output(stderr.decode("utf-8", errors="replace"))

        result = {
            "exit_code": proc.returncode,
            "stdout": stdout_str,
            "stderr": stderr_str,
        }

        # 简化输出：如果 stderr 为空则省略
        if not stderr_str.strip():
            del result["stderr"]

        result_text = json.dumps(result, indent=2, ensure_ascii=False)
        return [TextContent(type="text", text=result_text)]

    except asyncio.TimeoutError:
        # 尝试读取已产生的部分输出
        partial_stdout = ""
        partial_stderr = ""
        try:
            if proc.stdout and not proc.stdout.at_eof():
                raw = await proc.stdout.read(8192)
                partial_stdout = raw.decode("utf-8", errors="replace")
            if proc.stderr and not proc.stderr.at_eof():
                raw = await proc.stderr.read(4096)
                partial_stderr = raw.decode("utf-8", errors="replace")
        except Exception:
            pass
        # 杀整个进程组
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()  # fallback: 杀 shell
            except Exception:
                pass
        # 等待进程完全清理，防止僵尸进程
        try:
            await proc.communicate()
        except Exception:
            pass
        error_detail = {
            "exit_code": -1,
            "error": f"Command timed out after {timeout}s",
            "hint": "Try adding timeout flags to the command, or increase the timeout parameter",
        }
        if partial_stdout.strip():
            error_detail["partial_stdout"] = _truncate_output(partial_stdout)
        if partial_stderr.strip():
            error_detail["partial_stderr"] = _truncate_output(partial_stderr)
        return [TextContent(type="text", text=json.dumps(error_detail, indent=2, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]


async def http_request(args: dict):
    """HTTP 请求 — 复用连接池"""
    try:
        timeout = args.get("timeout", 30)
        follow_redirects = args.get("follow_redirects", True)
        client = await _get_http_client(timeout, follow_redirects)

        method = args.get("method", "GET").upper()
        url = args["url"]
        headers = args.get("headers", {})
        body = args.get("body", "")

        resp = await client.request(method, url, headers=headers, content=body if body else None)

        content = resp.text
        # 截断过长响应
        if len(content) > 15000:
            content = content[:7000] + f"\n\n... [RESPONSE TRUNCATED: {len(resp.text)} chars total] ...\n\n" + content[-5000:]

        result = {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": content,
            "url": str(resp.url),  # 显示最终URL（跟随重定向后）
        }
        result_text = json.dumps(result, indent=2, ensure_ascii=False)
        return [TextContent(type="text", text=result_text)]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, ensure_ascii=False))]


async def read_file(path: str, max_size: int = 50000):
    """读文件"""
    try:
        p = Path(path)
        if not p.exists():
            return [TextContent(type="text", text=f"File not found: {path}")]

        size = p.stat().st_size
        if size > max_size * 2:
            # 大文件：只读头部
            content = p.read_bytes()[:max_size].decode("utf-8", errors="replace")
            return [TextContent(
                type="text",
                text=f"[File: {path} | Size: {size} bytes | Showing first {max_size} chars]\n\n{content}",
            )]

        content = p.read_text(encoding="utf-8", errors="replace")
        if len(content) > max_size:
            content = content[:max_size] + f"\n\n... [TRUNCATED at {max_size} chars, total {len(content)}]"
        return [TextContent(type="text", text=content)]
    except Exception as e:
        return [TextContent(type="text", text=f"Error reading {path}: {e}")]


async def write_file(path: str, content: str):
    """写文件"""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return [TextContent(type="text", text=f"Written {len(content)} bytes to {path}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error writing {path}: {e}")]


# ============================================================================
# 记忆系统
# ============================================================================

MEMORY_FILE = str(PROJECT_ROOT / "logs" / "memory.json")
memory_store = {}
_memory_lock = asyncio.Lock()  # 保护并行 remember 调用


# ============================================================================
# 关键信息自动提取（Auto-Remember）
# ============================================================================

# 自动捕获规则 — 从工具输出中提取关键信息
_AUTO_EXTRACT_PATTERNS = {
    # 凭据类
    "credential": [
        re.compile(r'(?:username|user|login|account)\s*[:=]\s*["\']?(\S+)["\']?', re.IGNORECASE),
        re.compile(r'(?:password|passwd|pass|pwd)\s*[:=]\s*["\']?(\S+)["\']?', re.IGNORECASE),
    ],
    # 数据库连接字符串
    "db_connection": [
        re.compile(r'(?:mysql|postgres|mongodb|redis)://\S+', re.IGNORECASE),
        re.compile(r'jdbc:\S+', re.IGNORECASE),
    ],
    # API key / token
    "api_token": [
        re.compile(r'(?:api[_-]?key|token|secret[_-]?key|access[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', re.IGNORECASE),
    ],
    # 内网 IP
    "internal_ip": [
        re.compile(r'\b((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b'),
    ],
}


def _auto_extract_and_remember(output: str, source: str = "bash") -> str:
    """
    从工具输出中自动提取关键信息并存入记忆

    Note: 已禁用自动提取，改为AI主动调用remember工具
    避免误识别无关信息
    """
    # 禁用自动提取，AI应主动调用 remember 工具
    return ""


def _load_memory():
    global memory_store
    try:
        if os.path.exists(MEMORY_FILE):
            memory_store = json.loads(Path(MEMORY_FILE).read_text(encoding="utf-8"))
    except Exception:
        memory_store = {}


def _save_memory():
    try:
        Path(MEMORY_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(MEMORY_FILE).write_text(
            json.dumps(memory_store, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


async def store_memory(key: str, value: str, category: str = "general"):
    """存储记忆（带时间戳和分类，异步锁保护防止竞态）"""
    async with _memory_lock:
        _load_memory()
        memory_store[key] = {
            "value": value,
            "category": category,
            "timestamp": datetime.now().isoformat(),
        }
        _save_memory()
        count = len(memory_store)
    return [TextContent(type="text", text=f"Remembered: {key} [{category}] (total: {count} entries)")]


async def retrieve_memory(query: str):
    """检索记忆"""
    _load_memory()
    if not memory_store:
        return [TextContent(type="text", text="Memory is empty. Use 'remember' to store information.")]

    query_lower = query.lower()
    query_tokens = _tokenize(query_lower)
    if not query_tokens:
        query_tokens = [query_lower]

    # 搜索匹配 - OR 逻辑：任一 token 匹配即返回
    results = {}
    for k, v in memory_store.items():
        # 兼容旧格式（纯字符串）和新格式（带 category/timestamp）
        if isinstance(v, dict):
            val_str = v.get("value", "")
            cat = v.get("category", "general")
            searchable = f"{k} {val_str} {cat}".lower()
        else:
            val_str = str(v)
            searchable = f"{k} {val_str}".lower()

        if any(token in searchable for token in query_tokens):
            results[k] = v

    if not results:
        # 返回所有记忆的 key 列表帮助 AI
        all_keys = list(memory_store.keys())
        return [TextContent(
            type="text",
            text=f"No match for: {query}\nAvailable keys: {', '.join(all_keys[:20])}",
        )]

    return [TextContent(type="text", text=json.dumps(results, indent=2, ensure_ascii=False))]


# ============================================================================
# 比赛平台 API（严格对齐官方文档）
# ============================================================================

async def competition_api(method: str, endpoint: str, data: dict = None):
    """
    比赛平台 API 调用

    官方 API 文档:
    - GET  /api/challenges        获取赛题列表
    - POST /api/start_challenge   启动实例 {"code": "xxx"}
    - POST /api/stop_challenge    停止实例 {"code": "xxx"}
    - POST /api/submit            提交FLAG {"code": "xxx", "flag": "flag{xxx}"}
    - POST /api/hint              查看提示 {"code": "xxx"}（扣10%分）

    限频: 每秒3次（所有接口共享），0.35s 间隔
    """
    if not COMPETITION_HOST or not COMPETITION_TOKEN:
        return [TextContent(
            type="text",
            text="Competition not configured. Set COMPETITION_SERVER_HOST and COMPETITION_AGENT_TOKEN env vars.",
        )]

    # 限频 + 请求 + 重试 原子操作（防止并发竞态）
    async with _api_rate_lock:
        global _last_api_call_time
        # 限速等待
        now = time.time()
        elapsed = now - _last_api_call_time
        if elapsed < API_RATE_LIMIT_INTERVAL:
            await asyncio.sleep(API_RATE_LIMIT_INTERVAL - elapsed)

        try:
            host = COMPETITION_HOST
            if not host.startswith("http"):
                host = f"http://{host}"
            url = f"{host}{endpoint}"

            headers = {
                "Agent-Token": COMPETITION_TOKEN,
                "Content-Type": "application/json",
            }

            client = await _get_http_client(30, follow_redirects=True)
            if method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                resp = await client.post(url, headers=headers, json=data or {})

            # 处理限频 — 指数退避重试（仅一次）
            if resp.status_code == 429:
                await asyncio.sleep(2.0)  # 指数退避：首次重试等 2s
                if method == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.post(url, headers=headers, json=data or {})

            _last_api_call_time = time.time()

        except Exception as e:
            _last_api_call_time = time.time()
            return [TextContent(type="text", text=json.dumps({
                "error": str(e),
                "endpoint": endpoint,
                "hint": "Check COMPETITION_SERVER_HOST connectivity",
            }, ensure_ascii=False))]

    # 锁外处理响应（不占锁时间）
    if resp.status_code == 429:
        result = {
            "error": "Rate limited by competition server",
            "http_status": 429,
            "hint": "Too many requests. Wait 5+ seconds before retrying. "
                    "Rate limit: 3 requests/second shared across all API calls.",
        }
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]

    result = {}
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            result = resp.json()
        except Exception:
            result = {"_raw_response": resp.text[:2000]}
    else:
        result = {"_raw_response": resp.text[:2000]}

    # 增强返回信息
    if resp.status_code != 200:
        result["_http_status"] = resp.status_code
        status_hints = {
            400: "Bad request. Check parameters format.",
            401: "Invalid Agent-Token. Check COMPETITION_AGENT_TOKEN.",
            403: "Forbidden. Check permissions or slot availability.",
            404: "Endpoint or challenge not found. Check challenge code.",
            408: "Request timeout. Server may be overloaded.",
            429: "Rate limited. Wait before retrying.",
            500: "Server error. Retry in a few seconds.",
            502: "Bad gateway. Server may be restarting.",
            503: "Service unavailable. Server may be down.",
        }
        result["_hint"] = status_hints.get(resp.status_code, "Check error details above.")

    return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]


# ============================================================================
# 技能系统 — TF-IDF 搜索引擎（基于 skills_v2/SKILL.md 目录格式）
# ============================================================================

# TF-IDF 索引（启动时构建）
_skill_index = {}          # skill_name → {"terms": Counter, "meta": dict, "total_terms": int}
_idf_cache = {}            # term → IDF value
_index_built = False
_total_docs = 0


def _tokenize(text: str) -> list:
    """简单分词：提取英文单词 + 数字 + 中文字符"""
    if not text:
        return []
    # 英文单词和数字
    tokens = re.findall(r'[a-zA-Z][a-zA-Z0-9_\-]{1,}|[0-9]+', text.lower())
    # 中文字符（逐字提取，连续中文字符作为独立 token）
    cn_tokens = re.findall(r'[\u4e00-\u9fff]+', text.lower())
    tokens.extend(cn_tokens)
    return tokens


def _build_skill_index():
    """构建 TF-IDF 倒排索引（基于 skills_v2/SKILL.md）"""
    global _skill_index, _idf_cache, _index_built, _total_docs

    skills_dir = PROJECT_ROOT / "skills_v2"
    if not skills_dir.exists():
        return

    doc_freq = Counter()  # term → 出现在多少文档中

    for skill_dir in skills_dir.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue

        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")
            stem = skill_dir.name

            # 提取 frontmatter 元数据
            meta = _extract_skill_summary(content, stem)

            # 分词
            name_tokens = _tokenize(stem.replace("-", " "))
            desc_tokens = _tokenize(meta.get("description", ""))
            domain_tokens = _tokenize(meta.get("domain", ""))
            content_tokens = _tokenize(content)

            # 文件名和描述权重 3x（更重要）
            all_tokens = name_tokens * 3 + desc_tokens * 3 + domain_tokens * 2 + content_tokens
            term_counts = Counter(all_tokens)

            _skill_index[stem] = {
                "terms": term_counts,
                "meta": meta,
                "total_terms": len(all_tokens),
            }

            # 统计文档频率
            for term in set(all_tokens):
                doc_freq[term] += 1

        except Exception:
            continue

    _total_docs = len(_skill_index)
    if _total_docs == 0:
        return

    # 计算 IDF
    for term, df in doc_freq.items():
        _idf_cache[term] = math.log((_total_docs + 1) / (df + 1)) + 1  # smooth IDF

    _index_built = True


def _extract_skill_summary(content: str, fallback_name: str) -> dict:
    """从 Markdown frontmatter 提取摘要"""
    meta = {
        "name": fallback_name,
        "description": "",
        "domain": "",
        "preview": "",
    }
    # 提取 frontmatter
    match = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
    if match:
        try:
            front = yaml.safe_load(match.group(1))
            if isinstance(front, dict):
                meta["name"] = front.get("name", fallback_name)
                meta["description"] = front.get("description", "")
        except Exception:
            pass
    # 提取 domain
    domain_match = re.search(r'\*\*Domain\*\*:\s*(\S+)', content)
    if domain_match:
        meta["domain"] = domain_match.group(1)
    # 预览
    meta["preview"] = content[:300] + "..." if len(content) > 300 else content
    return meta


def _tfidf_search(query: str, top_k: int = 10) -> list:
    """TF-IDF 搜索，返回 [(skill_name, score, meta), ...]"""
    if not _index_built:
        _build_skill_index()

    if not _skill_index:
        return []

    query_tokens = _tokenize(query)
    if not query_tokens:
        return []

    scores = []
    for skill_name, doc in _skill_index.items():
        score = 0.0
        matched_terms = []
        total = doc["total_terms"] or 1

        for token in query_tokens:
            tf = doc["terms"].get(token, 0) / total
            idf = _idf_cache.get(token, 1.0)
            term_score = tf * idf
            if term_score > 0:
                score += term_score
                matched_terms.append(token)

        if score > 0:
            scores.append((skill_name, score, doc["meta"], matched_terms))

    # 排序：分数从高到低
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]


async def search_skills_handler(query: str):
    """搜索技能 — 优先使用 OpenSpace，回退到 TF-IDF"""
    skills_dir = PROJECT_ROOT / "skills_v2"
    if not skills_dir.exists():
        return [TextContent(type="text", text="Skills directory not found")]

    # 尝试使用 OpenSpace 技能引擎
    if SKILL_ENGINE_AVAILABLE:
        try:
            engine = get_skill_engine()
            if not engine._initialized:
                initialize_skill_engine(skills_dir)
            results = engine.search(query, top_k=10)

            if results:
                output = []
                for r in results:
                    output.append({
                        "name": r.get('name', ''),
                        "description": r.get('description', ''),
                        "relevance": r.get('score', 0),
                        "path": r.get('path', ''),
                    })
                return [TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]
        except Exception as e:
            print(f"[SkillEngine] OpenSpace search failed: {e}")

    # 回退：TF-IDF 搜索
    if not _index_built:
        _build_skill_index()

    results = _tfidf_search(query, top_k=10)

    if not results:
        # Fallback: 子串匹配（兜底）
        query_lower = query.lower()
        fallback = []
        for skill_dir in skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue
            if query_lower in skill_dir.name.lower():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    content = skill_file.read_text(encoding="utf-8", errors="replace")
                    meta = _extract_skill_summary(content, skill_dir.name)
                    fallback.append(meta)
        if fallback:
            return [TextContent(type="text", text=json.dumps(fallback[:10], indent=2, ensure_ascii=False))]

        # 返回全部 skill 名
        all_skills = sorted([d.name for d in skills_dir.iterdir() if d.is_dir() and (d / "SKILL.md").exists()])
        return [TextContent(
            type="text",
            text=f"No skills match: {query}\n\nAvailable skills ({len(all_skills)}):\n" +
                 "\n".join(f"  - {s}" for s in all_skills[:30]) +
                 ("\n  ... and more" if len(all_skills) > 30 else ""),
        )]

    # 构建结果
    output = []
    for skill_name, score, meta, matched_terms in results:
        entry = {
            "name": meta.get("name", skill_name),
            "file": skill_name,
            "description": meta.get("description", ""),
            "domain": meta.get("domain", ""),
            "relevance": round(score, 4),
            "matched": matched_terms[:5],
            "preview": meta.get("preview", "")[:200],
        }
        output.append(entry)

    return [TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]


async def read_skill_handler(name: str):
    """读取完整 skill 内容 — 优先使用 OpenSpace，回退到文件读取"""
    skills_dir = PROJECT_ROOT / "skills_v2"

    # 尝试使用 OpenSpace 技能引擎
    if SKILL_ENGINE_AVAILABLE:
        try:
            engine = get_skill_engine()
            if not engine._initialized:
                initialize_skill_engine(skills_dir)
            skill = engine.read_skill(name)
            if skill:
                content = f"# {skill.get('name', name)}\n\n"
                if skill.get('description'):
                    content += f"**Description**: {skill.get('description')}\n\n"
                if skill.get('tags'):
                    content += f"**Tags**: {', '.join(skill.get('tags', []))}\n\n"
                if skill.get('domain'):
                    content += f"**Domain**: {skill.get('domain')}\n\n"
                content += "---\n\n"
                content += skill.get('content', '')
                # 截断超长内容
                if len(content) > 30000:
                    content = content[:30000] + "\n\n... [SKILL TRUNCATED]"
                return [TextContent(type="text", text=content)]
        except Exception as e:
            print(f"[SkillEngine] OpenSpace read failed: {e}")

    # 回退：直接文件读取（skills_v2 目录格式）
    candidates = [
        skills_dir / name / "SKILL.md",
        skills_dir / name.lower() / "SKILL.md",
        skills_dir / name.replace("_", "-") / "SKILL.md",
        skills_dir / name.replace("-", "_") / "SKILL.md",
    ]

    for path in candidates:
        if path.exists():
            # 路径遍历保护：解析后的路径必须在 skills 目录内
            resolved = path.resolve()
            if not resolved.is_relative_to(skills_dir.resolve()):
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            # 截断超长 skill
            if len(content) > 30000:
                content = content[:30000] + "\n\n... [SKILL TRUNCATED]"
            return [TextContent(type="text", text=content)]

    # 未找到，列出相似名称
    available = sorted([d.name for d in skills_dir.iterdir()
                       if d.is_dir() and name.lower() in d.name.lower()])
    if available:
        return [TextContent(
            type="text",
            text=f"Skill '{name}' not found. Similar skills:\n" +
                 "\n".join(f"  - {s}" for s in available[:10]),
        )]

    return [TextContent(type="text", text=f"Skill '{name}' not found. Use search_skills to find available skills.")]



# ============================================================================
# OpenSpace 技能管理
# ============================================================================

SKILLS_DIR = PROJECT_ROOT / "skills_v2"


def create_skill_handler(name: str, content: str):
    """创建新的 skill 文件（skills_v2 目录格式）"""
    if not name:
        return [TextContent(type="text", text="Error: skill name is required")]

    # 安全检查：防止路径遍历
    safe_name = name.replace("..", "").replace("/", "_").replace("\\", "_")
    skill_dir = SKILLS_DIR / safe_name
    skill_path = skill_dir / "SKILL.md"

    # 检查是否已存在
    if skill_path.exists():
        return [TextContent(type="text", text=f"Warning: Skill '{name}' already exists. Use update_skill to modify.")]

    # 创建目录和文件
    skill_dir.mkdir(parents=True, exist_ok=True)
    skill_path.write_text(content, encoding="utf-8")

    # 重建搜索索引
    _build_skill_index()

    return [TextContent(type="text", text=f"Skill created: {safe_name}\nPath: {skill_path}")]


def update_skill_handler(name: str, content: str):
    """更新现有 skill 文件（覆盖模式）"""
    if not name:
        return [TextContent(type="text", text="Error: skill name is required")]

    safe_name = name.replace("..", "").replace("/", "_").replace("\\", "_")
    skill_dir = SKILLS_DIR / safe_name
    skill_path = skill_dir / "SKILL.md"

    if not skill_path.exists():
        return [TextContent(type="text", text=f"Error: Skill '{name}' not found. Use create_skill to create new skills.")]

    try:
        # 覆盖写入（AI 如需保留原有内容应自行包含）
        skill_path.write_text(content, encoding="utf-8")

        # 重建搜索索引
        _build_skill_index()

        return [TextContent(type="text", text=f"Skill updated: {safe_name}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: Failed to update skill - {e}")]


def list_skills_handler():
    """列出所有可用的 skill 文件（skills_v2 目录格式）"""
    if not SKILLS_DIR.exists():
        return [TextContent(type="text", text="Skills directory not found")]

    skills = []
    for skill_dir in SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            continue
        try:
            content = skill_file.read_text(encoding="utf-8")
            meta = _extract_skill_summary(content, skill_dir.name)
            name = meta.get("name", skill_dir.name)
            desc = meta.get("description", "No description")[:60]
            skills.append(f"  - {name}: {desc}...")
        except Exception:
            skills.append(f"  - {skill_dir.name}: (error reading)")

    if not skills:
        return [TextContent(type="text", text="No skills found")]

    result = f"Available skills ({len(skills)} total):\n" + "\n".join(skills)
    return [TextContent(type="text", text=result)]


async def _start_challenge_with_reset(code: str):
    """启动新题（包装器，预留给未来添加重置逻辑）"""
    return await competition_api("POST", "/api/start_challenge", {"code": code})


# ============================================================================
# MCP 启动
# ============================================================================

if __name__ == "__main__":
    from mcp.server.stdio import stdio_server

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(main())
