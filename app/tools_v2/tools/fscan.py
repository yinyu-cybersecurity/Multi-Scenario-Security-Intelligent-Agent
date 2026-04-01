"""
fscan内网综合扫描工具
"""

import asyncio
import os
import shutil
from typing import Dict, Any

from app.tools_v2.tool_factory import buildTool, ensure_result_format, get_tool_registry_v2
from app.agents.base import ToolPermission


async def fscan_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """fscan执行Handler"""
    target = params["target"]
    ports = params.get("ports", "")
    options = params.get("options", "")

    # fscan可能在不同路径
    fscan_path = shutil.which("fscan") or shutil.which("fscan.exe")
    if not fscan_path:
        # 尝试常见路径
        common_paths = ["./fscan", "./fscan.exe", "/usr/local/bin/fscan"]
        for path in common_paths:
            if os.path.exists(path):
                fscan_path = path
                break

    if not fscan_path:
        return ensure_result_format({
            "success": False,
            "error": "fscan未安装或不在PATH中"
        })

    cmd_parts = [fscan_path, "-h", target]

    if ports:
        cmd_parts.extend(["-p", ports])
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

        # 解析结果
        hosts = []
        services = []
        vulns = []

        for line in output.split('\n'):
            line = line.strip()
            # 解析存活主机
            if 'open' in line.lower() or 'alive' in line.lower():
                hosts.append(line)
            # 解析服务
            elif any(port in line for port in ['445', '139', '3389', '22', '80', '443']):
                services.append(line)
            # 解析漏洞
            elif 'vuln' in line.lower() or 'weak' in line.lower():
                vulns.append(line)

        return ensure_result_format({
            "success": True,
            "data": {
                "output": output,
                "hosts": hosts,
                "services": services,
                "vulnerabilities": vulns,
                "target": target
            }
        })

    except asyncio.TimeoutError:
        return ensure_result_format({"success": False, "error": "fscan扫描超时"})
    except Exception as e:
        return ensure_result_format({"success": False, "error": str(e)})


fscan_tool = buildTool(
    name="fscan",
    description="内网综合扫描工具，主机发现+端口扫描+漏洞检测",
    parameters=[
        {"name": "target", "type": "string", "required": True, "description": "目标IP或网段，如 192.168.1.0/24"},
        {"name": "ports", "type": "string", "required": False, "description": "端口范围，默认常用端口"},
        {"name": "options", "type": "string", "required": False, "description": "额外选项"}
    ],
    handler=fscan_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    timeout=300
)


def register_fscan():
    registry = get_tool_registry_v2()
    registry.register(fscan_tool)