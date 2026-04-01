"""
httpx HTTP探测工具
"""

import asyncio
import shutil
import json
from typing import Dict, Any

from app.tools_v2.tool_factory import buildTool, ensure_result_format, get_tool_registry_v2
from app.agents.base import ToolPermission


async def httpx_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """httpx执行Handler"""
    target = params["target"]
    ports = params.get("ports", "")
    options = params.get("options", "")

    if not shutil.which("httpx"):
        return ensure_result_format({
            "success": False,
            "error": "httpx未安装或不在PATH中"
        })

    cmd_parts = ["httpx", "-u", target, "-silent", "-json"]

    if ports:
        cmd_parts.extend(["-ports", ports])
    if options:
        cmd_parts.extend(options.split())

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=120
        )

        output = stdout.decode('utf-8', errors='replace')

        # 解析结果
        results = []
        for line in output.strip().split('\n'):
            if line.startswith('{'):
                try:
                    result = json.loads(line)
                    results.append({
                        "url": result.get("url", ""),
                        "status": result.get("status_code", 0),
                        "title": result.get("title", ""),
                        "webserver": result.get("webserver", ""),
                        "tech": result.get("tech", [])
                    })
                except:
                    pass

        return ensure_result_format({
            "success": True,
            "data": {
                "results": results,
                "target": target,
                "count": len(results)
            }
        })

    except asyncio.TimeoutError:
        return ensure_result_format({"success": False, "error": "httpx探测超时"})
    except Exception as e:
        return ensure_result_format({"success": False, "error": str(e)})


httpx_tool = buildTool(
    name="httpx",
    description="HTTP探测工具，快速发现Web服务",
    parameters=[
        {"name": "target", "type": "string", "required": True, "description": "目标地址或CIDR"},
        {"name": "ports", "type": "string", "required": False, "description": "端口列表，如 80,443,8080"},
        {"name": "options", "type": "string", "required": False, "description": "额外选项"}
    ],
    handler=httpx_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    timeout=120
)


def register_httpx():
    registry = get_tool_registry_v2()
    registry.register(httpx_tool)