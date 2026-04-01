"""
CTF安全工具MCP服务器

简化版：JSON Schema定义 + 简单Handler
"""

import asyncio
import subprocess
import shutil
import json
from typing import Dict, Any, Optional

# ============================================
# 工具定义 (JSON Schema)
# ============================================

TOOL_SCHEMAS = {
    "nmap": {
        "name": "nmap",
        "description": "端口扫描工具，发现目标开放端口和服务",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标地址或IP"
                },
                "ports": {
                    "type": "string",
                    "default": "1-1000",
                    "description": "端口范围"
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "full", "service"],
                    "default": "quick"
                }
            },
            "required": ["target"]
        }
    },

    "nuclei": {
        "name": "nuclei",
        "description": "漏洞扫描工具，使用模板检测CVE",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标URL"
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"]
                }
            },
            "required": ["target"]
        }
    },

    "httpx": {
        "name": "httpx",
        "description": "HTTP探测工具，快速发现Web服务",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标地址或CIDR"
                },
                "ports": {
                    "type": "string",
                    "description": "端口列表"
                }
            },
            "required": ["target"]
        }
    },

    "fscan": {
        "name": "fscan",
        "description": "内网综合扫描工具",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标IP或网段"
                },
                "ports": {
                    "type": "string",
                    "description": "端口范围"
                }
            },
            "required": ["target"]
        }
    },

    "sqlmap": {
        "name": "sqlmap",
        "description": "SQL注入自动化利用工具",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "format": "uri",
                    "description": "目标URL"
                },
                "level": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1
                },
                "action": {
                    "type": "string",
                    "enum": ["detect", "dbs", "tables", "dump"],
                    "default": "detect"
                }
            },
            "required": ["target_url"]
        }
    }
}


# ============================================
# 工具Handler (极简实现)
# ============================================

async def run_command(cmd: list, timeout: int = 300) -> Dict[str, Any]:
    """执行命令并返回结果"""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )
        return {
            "success": proc.returncode == 0,
            "stdout": stdout.decode('utf-8', errors='replace'),
            "stderr": stderr.decode('utf-8', errors='replace')
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": "超时"}
    except Exception as e:
        return {"success": False, "error": str(e)}


async def nmap_handler(target: str, ports: str = "1-1000", scan_type: str = "quick") -> Dict:
    """nmap执行"""
    if not shutil.which("nmap"):
        return {"success": False, "error": "nmap未安装"}

    cmd = ["nmap"]
    if scan_type == "quick":
        cmd.extend(["-T4", "-F", "-p", ports])
    elif scan_type == "full":
        cmd.extend(["-T4", "-Pn", "-p-"])
    elif scan_type == "service":
        cmd.extend(["-T4", "-sV", "-sC", "-p", ports])
    cmd.append(target)

    result = await run_command(cmd)
    if result["success"]:
        # 解析开放端口
        open_ports = []
        for line in result["stdout"].split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 2:
                    open_ports.append(parts[0].split('/')[0])
        result["open_ports"] = open_ports
    return result


async def nuclei_handler(target: str, severity: str = None) -> Dict:
    """nuclei执行"""
    if not shutil.which("nuclei"):
        return {"success": False, "error": "nuclei未安装"}

    cmd = ["nuclei", "-u", target, "-silent", "-json"]
    if severity:
        cmd.extend(["-severity", severity])

    result = await run_command(cmd)
    if result["success"]:
        # 解析漏洞
        vulns = []
        for line in result["stdout"].strip().split('\n'):
            if line.startswith('{'):
                try:
                    vulns.append(json.loads(line))
                except:
                    pass
        result["vulnerabilities"] = vulns
    return result


async def httpx_handler(target: str, ports: str = None) -> Dict:
    """httpx执行"""
    if not shutil.which("httpx"):
        return {"success": False, "error": "httpx未安装"}

    cmd = ["httpx", "-u", target, "-silent", "-json"]
    if ports:
        cmd.extend(["-ports", ports])

    result = await run_command(cmd, timeout=120)
    if result["success"]:
        results = []
        for line in result["stdout"].strip().split('\n'):
            if line.startswith('{'):
                try:
                    results.append(json.loads(line))
                except:
                    pass
        result["hosts"] = results
    return result


async def fscan_handler(target: str, ports: str = None) -> Dict:
    """fscan执行"""
    fscan_path = shutil.which("fscan") or shutil.which("fscan.exe") or "./fscan"
    cmd = [fscan_path, "-h", target]
    if ports:
        cmd.extend(["-p", ports])

    return await run_command(cmd)


async def sqlmap_handler(target_url: str, level: int = 1, action: str = "detect") -> Dict:
    """sqlmap执行"""
    sqlmap_path = shutil.which("sqlmap") or "sqlmap.py"

    cmd = [
        sqlmap_path, "-u", target_url,
        f"--level={level}",
        "--batch", "--random-agent"
    ]
    if action == "dbs":
        cmd.append("--dbs")
    elif action == "tables":
        cmd.append("--tables")
    elif action == "dump":
        cmd.append("--dump")

    result = await run_command(cmd, timeout=600)
    if result["success"]:
        result["vulnerable"] = "injection point" in result["stdout"].lower()
    return result


# ============================================
# 工具注册表
# ============================================

HANDLERS = {
    "nmap": nmap_handler,
    "nuclei": nuclei_handler,
    "httpx": httpx_handler,
    "fscan": fscan_handler,
    "sqlmap": sqlmap_handler,
}


def get_tool_schema(name: str) -> Optional[Dict]:
    """获取工具Schema"""
    return TOOL_SCHEMAS.get(name)


def list_tools() -> list:
    """列出所有工具"""
    return list(TOOL_SCHEMAS.keys())


def get_all_schemas() -> list:
    """获取所有工具Schema"""
    return list(TOOL_SCHEMAS.values())


async def execute_tool(name: str, params: Dict) -> Dict:
    """执行工具"""
    handler = HANDLERS.get(name)
    if not handler:
        return {"success": False, "error": f"未知工具: {name}"}

    try:
        return await handler(**params)
    except Exception as e:
        return {"success": False, "error": str(e)}