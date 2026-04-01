"""
nuclei漏洞扫描工具
"""

import asyncio
import shutil
import json
from typing import Dict, Any

from app.tools_v2.tool_factory import buildTool, ensure_result_format, get_tool_registry_v2
from app.agents.base import ToolPermission


async def nuclei_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """nuclei执行Handler"""
    target = params["target"]
    templates = params.get("templates", "")
    severity = params.get("severity", "")
    options = params.get("options", "")

    if not shutil.which("nuclei"):
        return ensure_result_format({
            "success": False,
            "error": "nuclei未安装或不在PATH中"
        })

    cmd_parts = ["nuclei", "-u", target, "-silent", "-json"]

    if templates:
        cmd_parts.extend(["-t", templates])
    if severity:
        cmd_parts.extend(["-severity", severity])
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
            timeout=300
        )

        output = stdout.decode('utf-8', errors='replace')

        # 解析发现的漏洞
        vulns = []
        for line in output.strip().split('\n'):
            if line.startswith('{'):
                try:
                    vuln = json.loads(line)
                    vulns.append({
                        "name": vuln.get("info", {}).get("name", "Unknown"),
                        "severity": vuln.get("info", {}).get("severity", "unknown"),
                        "template": vuln.get("template-id", ""),
                        "url": vuln.get("matched-at", target)
                    })
                except:
                    pass

        return ensure_result_format({
            "success": True,
            "data": {
                "vulnerabilities": vulns,
                "target": target,
                "count": len(vulns)
            }
        })

    except asyncio.TimeoutError:
        return ensure_result_format({"success": False, "error": "nuclei扫描超时"})
    except Exception as e:
        return ensure_result_format({"success": False, "error": str(e)})


nuclei_tool = buildTool(
    name="nuclei",
    description="漏洞扫描工具，使用模板检测CVE和其他漏洞",
    parameters=[
        {"name": "target", "type": "string", "required": True, "description": "目标URL"},
        {"name": "templates", "type": "string", "required": False, "description": "模板路径或标签"},
        {"name": "severity", "type": "string", "required": False, "enum": ["critical", "high", "medium", "low", "info"], "description": "严重程度过滤"},
        {"name": "options", "type": "string", "required": False, "description": "额外选项"}
    ],
    handler=nuclei_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    timeout=300
)


def register_nuclei():
    registry = get_tool_registry_v2()
    registry.register(nuclei_tool)