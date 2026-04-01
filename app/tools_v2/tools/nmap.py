"""
nmap端口扫描工具

借鉴Claude Code的工具设计模式
"""

import asyncio
import shutil
from typing import Dict, Any

from app.tools_v2.tool_factory import buildTool, ensure_result_format, get_tool_registry_v2
from app.agents.base import ToolPermission


async def nmap_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    nmap执行Handler

    Args:
        params: 工具参数
            - target: 目标地址/IP
            - ports: 端口范围 (可选，默认1-1000)
            - scan_type: 扫描类型 (quick/full/service)
            - options: 额外选项 (可选)

    Returns:
        执行结果
    """
    target = params["target"]
    ports = params.get("ports", "1-1000")
    scan_type = params.get("scan_type", "quick")
    options = params.get("options", "")

    # 检查nmap是否可用
    if not shutil.which("nmap"):
        return ensure_result_format({
            "success": False,
            "error": "nmap未安装或不在PATH中"
        })

    # 构建命令
    cmd_parts = ["nmap"]

    # 扫描类型
    if scan_type == "quick":
        cmd_parts.extend(["-T4", "-F"])  # 快速扫描
    elif scan_type == "full":
        cmd_parts.extend(["-T4", "-p-", "-Pn"])
    elif scan_type == "service":
        cmd_parts.extend(["-T4", "-sV", "-sC"])
    else:
        cmd_parts.extend(["-T4"])

    # 端口范围
    if scan_type != "full":
        cmd_parts.extend(["-p", ports])

    # 目标
    cmd_parts.append(target)

    # 额外选项
    if options:
        cmd_parts.extend(options.split())

    try:
        # 执行命令
        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=300  # 5分钟超时
        )

        output = stdout.decode('utf-8', errors='replace')
        error_output = stderr.decode('utf-8', errors='replace')

        if proc.returncode != 0:
            return ensure_result_format({
                "success": False,
                "error": f"nmap执行失败: {error_output}",
                "data": {"output": output}
            })

        # 解析开放端口
        open_ports = []
        for line in output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0].split('/')[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    open_ports.append(port_info)

        return ensure_result_format({
            "success": True,
            "data": {
                "output": output,
                "open_ports": open_ports,
                "target": target,
                "scan_type": scan_type
            }
        })

    except asyncio.TimeoutError:
        return ensure_result_format({
            "success": False,
            "error": "nmap扫描超时"
        })
    except Exception as e:
        return ensure_result_format({
            "success": False,
            "error": f"执行错误: {str(e)}"
        })


# 定义工具
nmap_tool = buildTool(
    name="nmap",
    description="端口扫描工具，用于发现目标开放端口和服务",
    parameters=[
        {
            "name": "target",
            "type": "string",
            "required": True,
            "description": "目标地址或IP，如 192.168.1.1 或 example.com"
        },
        {
            "name": "ports",
            "type": "string",
            "required": False,
            "default": "1-1000",
            "description": "端口范围，如 80,443 或 1-65535"
        },
        {
            "name": "scan_type",
            "type": "string",
            "required": False,
            "default": "quick",
            "enum": ["quick", "full", "service"],
            "description": "扫描类型：quick快速，full全端口，service服务识别"
        },
        {
            "name": "options",
            "type": "string",
            "required": False,
            "description": "额外nmap选项"
        }
    ],
    handler=nmap_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    timeout=300
)


def register_nmap():
    """注册nmap工具"""
    registry = get_tool_registry_v2()
    registry.register(nmap_tool)