"""
CTF工具定义 - 基础工具集

实现Claude Code的buildTool模式:
- 声明式Schema定义
- Zod风格参数验证
- ToolRegistry注册
"""

from typing import Dict, Any, Optional, List
import asyncio
import httpx
import re
import logging

from app.tools_v2.tool_factory import (
    buildTool,
    get_tool_registry_v2,
    ParamType,
)
from app.tools_v2.native_executor import get_native_executor
from app.agents.base import ToolPermission

logger = logging.getLogger(__name__)


# ============================================
# 工具Handler实现
# ============================================

async def http_request_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    HTTP请求工具Handler

    支持GET/POST/PUT/DELETE方法
    """
    url = params.get("url")
    method = params.get("method", "GET").upper()
    headers = params.get("headers", {})
    data = params.get("data")
    timeout = params.get("timeout", 30)

    if not url:
        return {"success": False, "error": "URL is required"}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, headers=headers, data=data)
            elif method == "PUT":
                response = await client.put(url, headers=headers, data=data)
            elif method == "DELETE":
                response = await client.delete(url, headers=headers)
            else:
                return {"success": False, "error": f"Unsupported method: {method}"}

            # 提取关键响应信息
            result = {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:50000],  # 限制大小
                "content_length": len(response.content),
            }

            # 检测常见漏洞特征
            content_lower = response.text.lower()
            if "flag{" in content_lower or "ctf{" in content_lower:
                result["flag_detected"] = True
            if "error" in content_lower and "sql" in content_lower:
                result["sqli_hint"] = True
            if "<!--" in response.text:
                result["html_comments"] = True

            return result

    except httpx.TimeoutException:
        return {"success": False, "error": f"Request timeout after {timeout}s"}
    except httpx.RequestError as e:
        return {"success": False, "error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}


async def run_command_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    命令执行工具Handler

    使用NativeExecutor执行系统工具
    """
    command = params.get("command")
    timeout = params.get("timeout", 120)

    if not command:
        return {"success": False, "error": "Command is required"}

    # 安全检查：仅允许白名单工具
    allowed_tools = [
        "nuclei", "httpx", "ffuf", "subfinder",
        "curl", "wget", "dirb", "gobuster",
        "fscan", "frpc", "frps", "sqlmap", "xray"
    ]

    # 解析命令获取工具名
    parts = command.split()
    if not parts:
        return {"success": False, "error": "Empty command"}

    tool_name = parts[0].lower()

    # Windows下处理
    if tool_name.endswith(".exe"):
        tool_name = tool_name[:-4]

    if tool_name not in allowed_tools:
        return {
            "success": False,
            "error": f"Tool '{tool_name}' not in allowed list: {allowed_tools}"
        }

    try:
        executor = get_native_executor()

        # 检查工具可用性
        availability = await executor.check_available(tool_name)
        if not availability.is_available:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' not available: {availability.error}",
                "hint": availability.error
            }

        # 执行命令
        args = parts[1:] if len(parts) > 1 else []
        result = await executor.execute(
            tool_name=tool_name,
            args=args,
            timeout=timeout * 1000  # 转换为毫秒
        )

        return result

    except Exception as e:
        return {"success": False, "error": f"Execution error: {str(e)}"}


async def analyze_response_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    响应分析工具Handler

    分析HTTP响应提取有用信息
    """
    response = params.get("response", "")
    look_for = params.get("look_for", "flags")

    if not response:
        return {"success": False, "error": "Response content is required"}

    result = {
        "success": True,
        "look_for": look_for,
        "findings": []
    }

    try:
        if look_for == "flags":
            # 搜索FLAG格式
            flag_patterns = [
                r'flag\{[^}]+\}',
                r'FLAG\{[^}]+\}',
                r'ctf\{[^}]+\}',
                r'CTF\{[^}]+\}',
                r'hctf\{[^}]+\}',
                r'ACTF\{[^}]+\}',
            ]
            for pattern in flag_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                for match in matches:
                    if match not in result["findings"]:
                        result["findings"].append(match)

        elif look_for == "links":
            # 提取链接
            link_patterns = [
                r'href=["\']([^"\']+)["\']',
                r'src=["\']([^"\']+)["\']',
                r'https?://[^\s<>"]+',
            ]
            for pattern in link_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                result["findings"].extend(matches[:20])  # 限制数量

        elif look_for == "forms":
            # 提取表单
            form_pattern = r'<form[^>]*>.*?</form>'
            matches = re.findall(form_pattern, response, re.DOTALL | re.IGNORECASE)
            result["findings"] = matches[:10]

        elif look_for == "comments":
            # 提取HTML注释
            comment_pattern = r'<!--(.*?)-->'
            matches = re.findall(comment_pattern, response, re.DOTALL)
            result["findings"] = [m.strip() for m in matches if m.strip()][:20]

        elif look_for == "errors":
            # 搜索错误信息
            error_patterns = [
                r'error[:\s]+([^\n]+)',
                r'exception[:\s]+([^\n]+)',
                r'warning[:\s]+([^\n]+)',
                r'sql[^<]*error',
                r'stack trace[:\s]*([^\n]+)',
            ]
            for pattern in error_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                result["findings"].extend(matches[:10])

        result["count"] = len(result["findings"])
        return result

    except Exception as e:
        return {"success": False, "error": f"Analysis error: {str(e)}"}


# ============================================
# 工具注册
# ============================================

def register_ctf_tools():
    """注册所有CTF工具到Registry"""

    registry = get_tool_registry_v2()

    # 1. 注册基础工具（http_request, run_command, analyze_response）
    http_tool = buildTool(
        name="http_request",
        description="发送HTTP请求获取目标URL内容，支持GET/POST/PUT/DELETE方法",
        parameters=[
            {
                "name": "url",
                "type": "uri",
                "required": True,
                "description": "目标URL"
            },
            {
                "name": "method",
                "type": "string",
                "required": False,
                "description": "HTTP方法",
                "enum": ["GET", "POST", "PUT", "DELETE"],
                "default": "GET"
            },
            {
                "name": "headers",
                "type": "object",
                "required": False,
                "description": "请求头字典"
            },
            {
                "name": "data",
                "type": "string",
                "required": False,
                "description": "请求体数据（POST/PUT）"
            },
            {
                "name": "timeout",
                "type": "integer",
                "required": False,
                "description": "超时时间（秒）",
                "min": 1,
                "max": 300,
                "default": 30
            }
        ],
        handler=http_request_handler,
        permissions=[ToolPermission.NETWORK],
        timeout=60,
    )
    registry.register(http_tool)

    # 2. 命令执行工具
    command_tool = buildTool(
        name="run_command",
        description="执行系统命令（安全工具：sqlmap, nuclei, curl, xray等）",
        parameters=[
            {
                "name": "command",
                "type": "string",
                "required": True,
                "description": "要执行的完整命令"
            },
            {
                "name": "timeout",
                "type": "integer",
                "required": False,
                "description": "超时时间（秒）",
                "min": 1,
                "max": 600,
                "default": 120
            }
        ],
        handler=run_command_handler,
        permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
        timeout=180,
    )
    registry.register(command_tool)

    # 3. 响应分析工具
    analyze_tool = buildTool(
        name="analyze_response",
        description="分析HTTP响应，提取flags、链接、表单、注释、错误信息",
        parameters=[
            {
                "name": "response",
                "type": "string",
                "required": True,
                "description": "HTTP响应内容"
            },
            {
                "name": "look_for",
                "type": "string",
                "required": False,
                "description": "查找类型",
                "enum": ["flags", "links", "forms", "comments", "errors"],
                "default": "flags"
            }
        ],
        handler=analyze_response_handler,
        permissions=[],  # 无特殊权限要求
        timeout=30,
    )
    registry.register(analyze_tool)

    # 4. 注册ToolSearch工具（搜索延迟加载的工具）
    from app.tools_v2.deferred_loader import tool_search_handler
    search_tool = buildTool(
        name="ToolSearch",
        description="搜索可用的安全工具（包括延迟加载的工具），根据关键词查找相关工具",
        parameters=[
            {
                "name": "query",
                "type": "string",
                "required": True,
                "description": "搜索关键词，如 'sql', 'xss', 'crypto', 'scan'"
            }
        ],
        handler=tool_search_handler,
        permissions=[],  # 无特殊权限要求
        timeout=10,
        is_read_only=True,
        is_concurrency_safe=True,
    )
    registry.register(search_tool)

    # 5. 注册simple_tools中的专业工具
    from app.tools_v2.tools import register_tools
    register_tools(registry)

    logger.info(f"Registered {len(registry.list_tools())} CTF tools: {registry.list_tools()}")


def get_tools_for_api() -> List[Dict[str, Any]]:
    """
    获取工具Schema供LLM API使用

    返回智谱API兼容的tools格式
    """
    registry = get_tool_registry_v2()
    schemas = registry.get_all_schemas()

    # 转换为智谱API格式
    tools = []
    for schema in schemas:
        tools.append({
            "type": "function",
            "function": schema
        })

    return tools


__all__ = [
    "register_ctf_tools",
    "get_tools_for_api",
    "http_request_handler",
    "run_command_handler",
    "analyze_response_handler",
]