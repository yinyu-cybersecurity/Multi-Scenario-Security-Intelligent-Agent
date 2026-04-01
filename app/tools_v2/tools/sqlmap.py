"""
sqlmap SQL注入自动化利用工具
"""

import asyncio
import shutil
from typing import Dict, Any

from app.tools_v2.tool_factory import buildTool, ensure_result_format, get_tool_registry_v2
from app.agents.base import ToolPermission


async def sqlmap_handler(params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """sqlmap执行Handler"""
    target_url = params["target_url"]
    level = params.get("level", 1)
    risk = params.get("risk", 1)
    action = params.get("action", "detect")
    options = params.get("options", "")

    if not shutil.which("sqlmap"):
        # 尝试python sqlmap
        sqlmap_path = shutil.which("sqlmap.py")
        if not sqlmap_path:
            return ensure_result_format({
                "success": False,
                "error": "sqlmap未安装"
            })
    else:
        sqlmap_path = "sqlmap"

    cmd_parts = [
        sqlmap_path,
        "-u", target_url,
        f"--level={level}",
        f"--risk={risk}",
        "--batch",  # 非交互模式
        "--random-agent"
    ]

    # 根据action添加参数
    if action == "dbs":
        cmd_parts.append("--dbs")
    elif action == "tables":
        cmd_parts.append("--tables")
    elif action == "dump":
        cmd_parts.append("--dump")
    elif action == "shell":
        cmd_parts.append("--os-shell")

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
            timeout=600  # 10分钟超时
        )

        output = stdout.decode('utf-8', errors='replace')

        # 分析结果
        is_vulnerable = "sqlmap identified the following injection point" in output or \
                       "Parameter:" in output and "Type:" in output

        databases = []
        if "available databases" in output:
            # 提取数据库名
            import re
            db_match = re.search(r'\[\*\] (.+)', output[output.find("available databases"):])
            if db_match:
                databases = [db.strip() for db in db_match.group(1).split(',')]

        return ensure_result_format({
            "success": True,
            "data": {
                "output": output,
                "vulnerable": is_vulnerable,
                "databases": databases,
                "target": target_url,
                "action": action
            }
        })

    except asyncio.TimeoutError:
        return ensure_result_format({"success": False, "error": "sqlmap执行超时"})
    except Exception as e:
        return ensure_result_format({"success": False, "error": str(e)})


sqlmap_tool = buildTool(
    name="sqlmap",
    description="SQL注入自动化利用工具",
    parameters=[
        {"name": "target_url", "type": "string", "required": True, "format": "uri", "description": "目标URL，需包含参数"},
        {"name": "level", "type": "integer", "required": False, "default": 1, "min": 1, "max": 5, "description": "测试等级(1-5)"},
        {"name": "risk", "type": "integer", "required": False, "default": 1, "min": 1, "max": 3, "description": "风险等级(1-3)"},
        {"name": "action", "type": "string", "required": False, "default": "detect", "enum": ["detect", "dbs", "tables", "dump", "shell"], "description": "操作类型"},
        {"name": "options", "type": "string", "required": False, "description": "额外选项"}
    ],
    handler=sqlmap_handler,
    permissions=[ToolPermission.EXECUTE, ToolPermission.NETWORK],
    timeout=600
)


def register_sqlmap():
    registry = get_tool_registry_v2()
    registry.register(sqlmap_tool)