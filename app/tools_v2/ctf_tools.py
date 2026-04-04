# app/tools_v2/ctf_tools.py

"""
CTF工具定义 - 极简版本

严格遵循计划.txt，只保留核心工具：
- 核心工具: http_request, bash
- 知识工具: load_skill, list_skills
- 记忆工具: remember, recall
- Web工具: sqlmap, ffuf
- 信息收集: nmap, nuclei
- 内网: fscan
- 云安全: 云存储检测, 云元数据
- AI安全: AI模型探测

总计约25个工具
"""

from typing import Dict, Any
import asyncio
import httpx
import json
import os

from app.tools_v2.tool_factory import buildTool, get_tool_registry_v2
from app.tools_v2.tool_result import ToolResult
from app.agents.base import ToolPermission


# ============================================
# 比赛平台配置
# ============================================

def get_competition_config() -> Dict[str, str]:
    """获取比赛平台配置"""
    return {
        "server_host": os.environ.get("COMPETITION_SERVER_HOST", ""),
        "agent_token": os.environ.get("COMPETITION_AGENT_TOKEN", ""),
    }


async def competition_api_call(method: str, endpoint: str, data: Dict = None) -> Dict:
    """调用比赛平台API"""
    config = get_competition_config()
    if not config["server_host"] or not config["agent_token"]:
        return {"code": -1, "message": "比赛平台未配置SERVER_HOST或AGENT_TOKEN"}

    url = f"http://{config['server_host']}{endpoint}"
    headers = {
        "Agent-Token": config["agent_token"],
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=30) as client:
        if method == "GET":
            response = await client.get(url, headers=headers)
        else:
            response = await client.post(url, headers=headers, json=data or {})

        return response.json()


# ============================================
# 工具Handler实现
# ============================================

async def http_request_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """HTTP请求工具"""
    url = params.get("url")
    method = params.get("method", "GET").upper()
    headers = params.get("headers", {})
    data = params.get("data")
    timeout = params.get("timeout", 30)

    if not url:
        return ToolResult(success=False, data=None, error="URL is required")

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
                return ToolResult(success=False, data=None, error=f"Unsupported method: {method}")

            result = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content": response.text[:50000],
            }

            # 检测FLAG
            if "flag{" in response.text.lower() or "ctf{" in response.text.lower():
                result["flag_detected"] = True

            return ToolResult(success=True, data=result)

    except Exception as e:
        return ToolResult(success=False, data=None, error=str(e))


async def bash_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """命令执行工具"""
    command = params.get("command")
    timeout = params.get("timeout", 120)

    if not command:
        return ToolResult(success=False, data=None, error="Command is required")

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )

        result = {
            "stdout": stdout.decode("utf-8", errors="ignore")[:10000],
            "stderr": stderr.decode("utf-8", errors="ignore")[:5000],
            "return_code": proc.returncode
        }

        return ToolResult(success=True, data=result)

    except asyncio.TimeoutError:
        return ToolResult(success=False, data=None, error=f"Timeout after {timeout}s")
    except Exception as e:
        return ToolResult(success=False, data=None, error=str(e))


async def remember_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """记录发现"""
    key = params.get("key")
    value = params.get("value")

    if not key:
        return ToolResult(success=False, data=None, error="Key is required")

    # TODO: 写入Memory
    return ToolResult(success=True, data={"message": f"Remembered: {key}"})


async def recall_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """回忆发现"""
    key = params.get("key")

    # TODO: 从Memory读取
    return ToolResult(success=True, data={"message": f"Recall: {key}"})


# ============================================
# 比赛平台工具Handler
# ============================================

async def list_challenges_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """获取赛题列表"""
    result = await competition_api_call("GET", "/api/challenges")
    if result.get("code") == 0:
        return ToolResult(success=True, data=result.get("data"))
    return ToolResult(success=False, data=None, error=result.get("message"))


async def start_challenge_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """启动赛题实例"""
    code = params.get("code")
    if not code:
        return ToolResult(success=False, data=None, error="赛题code必填")
    result = await competition_api_call("POST", "/api/start_challenge", {"code": code})
    if result.get("code") == 0:
        return ToolResult(success=True, data=result.get("data"))
    return ToolResult(success=False, data=None, error=result.get("message"))


async def stop_challenge_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """停止赛题实例"""
    code = params.get("code")
    if not code:
        return ToolResult(success=False, data=None, error="赛题code必填")
    result = await competition_api_call("POST", "/api/stop_challenge", {"code": code})
    if result.get("code") == 0:
        return ToolResult(success=True, data={"message": result.get("message")})
    return ToolResult(success=False, data=None, error=result.get("message"))


async def submit_flag_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """提交Flag"""
    code = params.get("code")
    flag = params.get("flag")
    if not code or not flag:
        return ToolResult(success=False, data=None, error="赛题code和flag必填")
    result = await competition_api_call("POST", "/api/submit", {"code": code, "flag": flag})
    if result.get("code") == 0:
        data = result.get("data", {})
        return ToolResult(
            success=data.get("correct", False),
            data=data,
            error="" if data.get("correct") else data.get("message")
        )
    return ToolResult(success=False, data=None, error=result.get("message"))


async def view_hint_handler(params: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
    """查看提示（会扣分）"""
    code = params.get("code")
    if not code:
        return ToolResult(success=False, data=None, error="赛题code必填")
    result = await competition_api_call("POST", "/api/hint", {"code": code})
    if result.get("code") == 0:
        return ToolResult(success=True, data=result.get("data"))
    return ToolResult(success=False, data=None, error=result.get("message"))


# ============================================
# 工具注册
# ============================================

def register_ctf_tools():
    """注册所有CTF工具"""
    registry = get_tool_registry_v2()

    # 1. 核心工具
    registry.register(buildTool(
        name="http_request",
        description="发送HTTP请求获取目标URL内容",
        parameters=[
            {"name": "url", "type": "string", "required": True, "description": "目标URL"},
            {"name": "method", "type": "string", "required": False, "description": "HTTP方法", "default": "GET"},
            {"name": "headers", "type": "object", "required": False, "description": "请求头"},
            {"name": "data", "type": "string", "required": False, "description": "请求体"},
            {"name": "timeout", "type": "integer", "required": False, "description": "超时秒数", "default": 30},
        ],
        handler=http_request_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="bash",
        description="执行系统命令",
        parameters=[
            {"name": "command", "type": "string", "required": True, "description": "命令"},
            {"name": "timeout", "type": "integer", "required": False, "description": "超时秒数", "default": 120},
        ],
        handler=bash_handler,
        permissions=[ToolPermission.EXECUTE],
    ))

    # 删除冗余的load_skill/list_skills
    # AI应该直接使用OpenSpace MCP工具:
    # - openspace__search_skills: 搜索skill
    # - openspace__execute_task: 执行任务（自动加载相关skill）

    # 3. 记忆工具
    registry.register(buildTool(
        name="remember",
        description="记录发现",
        parameters=[
            {"name": "key", "type": "string", "required": True, "description": "键"},
            {"name": "value", "type": "string", "required": True, "description": "值"},
        ],
        handler=remember_handler,
        permissions=[],
    ))

    registry.register(buildTool(
        name="recall",
        description="回忆发现",
        parameters=[
            {"name": "key", "type": "string", "required": False, "description": "键（可选，不填则返回所有）"},
        ],
        handler=recall_handler,
        permissions=[],
    ))

    # 4. Web漏洞利用（通过bash调用）
    for tool in ["sqlmap", "ffuf", "nmap", "nuclei", "fscan"]:
        registry.register(buildTool(
            name=tool,
            description=f"{tool}工具（通过bash调用）",
            parameters=[
                {"name": "args", "type": "string", "required": True, "description": "命令参数"},
                {"name": "timeout", "type": "integer", "required": False, "description": "超时秒数", "default": 300},
            ],
            handler=lambda p, c, t=tool: bash_handler({"command": f"{t} {p.get('args', '')}", "timeout": p.get("timeout", 300)}, c),
            permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
        ))

    # 5. 云安全工具
    registry.register(buildTool(
        name="cloud_storage_check",
        description="云存储桶检测",
        parameters=[
            {"name": "bucket_url", "type": "string", "required": True, "description": "存储桶URL"},
        ],
        handler=lambda p, c: ToolResult(success=True, data={"message": "Cloud storage check"}),
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="cloud_metadata",
        description="云环境元数据获取",
        parameters=[],
        handler=lambda p, c: ToolResult(success=True, data={"message": "Cloud metadata"}),
        permissions=[ToolPermission.NETWORK],
    ))

    # 6. AI安全工具
    registry.register(buildTool(
        name="ai_probe",
        description="AI模型探测",
        parameters=[
            {"name": "target", "type": "string", "required": True, "description": "目标URL"},
        ],
        handler=lambda p, c: ToolResult(success=True, data={"message": "AI probe"}),
        permissions=[ToolPermission.NETWORK],
    ))

    # 7. 比赛平台工具
    registry.register(buildTool(
        name="list_challenges",
        description="获取当前可用的赛题列表",
        parameters=[],
        handler=list_challenges_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="start_challenge",
        description="启动指定赛题的容器实例",
        parameters=[
            {"name": "code", "type": "string", "required": True, "description": "赛题唯一标识"},
        ],
        handler=start_challenge_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="stop_challenge",
        description="停止指定赛题的容器实例",
        parameters=[
            {"name": "code", "type": "string", "required": True, "description": "赛题唯一标识"},
        ],
        handler=stop_challenge_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="submit_flag",
        description="提交赛题的Flag答案",
        parameters=[
            {"name": "code", "type": "string", "required": True, "description": "赛题唯一标识"},
            {"name": "flag", "type": "string", "required": True, "description": "Flag值（格式如flag{...}）"},
        ],
        handler=submit_flag_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    registry.register(buildTool(
        name="view_hint",
        description="查看赛题提示（会扣除该题总分的10%）",
        parameters=[
            {"name": "code", "type": "string", "required": True, "description": "赛题唯一标识"},
        ],
        handler=view_hint_handler,
        permissions=[ToolPermission.NETWORK],
    ))

    # 注册Meta工具
    from app.tools_v2.tools import register_meta_tools
    register_meta_tools(registry)


__all__ = ["register_ctf_tools"]