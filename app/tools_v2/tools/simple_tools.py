"""
CTF安全工具MCP服务器

简化版：JSON Schema定义 + 简单Handler

安全特性:
- 参数验证 - 验证target/IP格式
- SSRF防护 - 阻止私有IP访问
- 命令注入防护 - 参数化执行
"""

import asyncio
import subprocess
import shutil
import json
import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Tuple


# ============================================
# 安全验证函数
# ============================================

def validate_target(target: str) -> Tuple[bool, str]:
    """
    验证目标地址格式

    Args:
        target: 目标地址（IP或域名）

    Returns:
        (is_valid, error_message)
    """
    if not target or not isinstance(target, str):
        return False, "目标地址不能为空"

    # 基本长度限制
    if len(target) > 253:
        return False, "目标地址过长"

    # IP地址验证
    try:
        ipaddress.ip_address(target)
        return True, ""
    except ValueError:
        pass

    # CIDR验证
    try:
        ipaddress.ip_network(target, strict=False)
        return True, ""
    except ValueError:
        pass

    # 域名验证（简单正则）
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(domain_pattern, target):
        return True, ""

    return False, f"无效的目标地址格式: {target}"


def validate_url_for_ssrf(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """
    验证URL防止SSRF攻击

    Args:
        url: 待验证的URL
        allow_private: 是否允许私有IP（内网扫描场景）

    Returns:
        (is_valid, error_message)
    """
    try:
        parsed = urlparse(url)

        # 检查协议
        if parsed.scheme not in ['http', 'https']:
            return False, f"不支持的协议: {parsed.scheme}"

        # 获取主机名
        hostname = parsed.hostname
        if not hostname:
            return False, "无效的URL：缺少主机名"

        # 解析IP
        try:
            ip = ipaddress.ip_address(hostname)

            # 检查是否为私有IP
            if not allow_private and ip.is_private:
                return False, f"SSRF防护：禁止访问私有IP {hostname}。如需内网扫描，请使用allow_private=True"

            # 检查回环地址
            if ip.is_loopback and not allow_private:
                return False, f"SSRF防护：禁止访问回环地址"

            # 检查链路本地地址
            if ip.is_link_local and not allow_private:
                return False, f"SSRF防护：禁止访问链路本地地址"

        except ValueError:
            # 不是IP地址，可能是域名
            # 域名情况下的SSRF防护需要DNS解析，这里简化处理
            pass

        return True, ""
    except Exception as e:
        return False, f"URL验证错误: {str(e)}"


def validate_ports(ports: str) -> Tuple[bool, str]:
    """
    验证端口范围格式

    Args:
        ports: 端口范围字符串

    Returns:
        (is_valid, error_message)
    """
    if not ports:
        return True, ""  # 允许空，使用默认值

    # 单个端口
    if ports.isdigit():
        port = int(ports)
        if 1 <= port <= 65535:
            return True, ""
        return False, f"端口号超出范围: {port}"

    # 端口范围 (如 1-1000)
    if '-' in ports:
        parts = ports.split('-')
        if len(parts) == 2:
            try:
                start, end = int(parts[0]), int(parts[1])
                if 1 <= start <= end <= 65535:
                    return True, ""
                return False, f"端口范围无效: {ports}"
            except ValueError:
                return False, f"端口范围格式错误: {ports}"

    # 端口列表 (如 80,443,8080)
    if ',' in ports:
        try:
            for p in ports.split(','):
                port = int(p.strip())
                if not 1 <= port <= 65535:
                    return False, f"端口号超出范围: {port}"
            return True, ""
        except ValueError:
            return False, f"端口列表格式错误: {ports}"

    return False, f"无法识别的端口格式: {ports}"

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
    },

    "ffuf": {
        "name": "ffuf",
        "description": "快速Web模糊测试工具，用于目录枚举和参数发现",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "format": "uri",
                    "description": "目标URL（使用FUZZ关键字标记测试点）"
                },
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                    "description": "字典文件路径"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dir", "fuzz", "param"],
                    "default": "dir",
                    "description": "模式：目录枚举/模糊测试/参数发现"
                },
                "extensions": {
                    "type": "string",
                    "description": "文件扩展名，如 .php,.html"
                }
            },
            "required": ["target_url"]
        }
    },

    "dirsearch": {
        "name": "dirsearch",
        "description": "高级目录扫描工具，支持多线程和扩展名枚举",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "format": "uri",
                    "description": "目标URL"
                },
                "extensions": {
                    "type": "string",
                    "default": "php,html,js",
                    "description": "文件扩展名"
                },
                "wordlist": {
                    "type": "string",
                    "description": "自定义字典路径"
                },
                "recursive": {
                    "type": "boolean",
                    "default": False,
                    "description": "是否递归扫描"
                }
            },
            "required": ["target_url"]
        }
    },

    "gobuster": {
        "name": "gobuster",
        "description": "多协议爆破工具，支持目录、DNS、S3存储桶枚举",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标地址或域名"
                },
                "mode": {
                    "type": "string",
                    "enum": ["dir", "dns", "s3"],
                    "default": "dir",
                    "description": "模式：目录爆破/DNS枚举/S3存储桶"
                },
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/dirb/common.txt",
                    "description": "字典文件路径"
                },
                "extensions": {
                    "type": "string",
                    "description": "文件扩展名（dir模式）"
                },
                "threads": {
                    "type": "integer",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 100,
                    "description": "并发线程数"
                }
            },
            "required": ["target"]
        }
    },

    "whatweb": {
        "name": "whatweb",
        "description": "Web技术栈识别工具，检测CMS、框架、中间件等",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标URL或域名"
                },
                "aggression": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4,
                    "default": 1,
                    "description": "激进程度：1=被动，4=主动探测"
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "详细输出模式"
                }
            },
            "required": ["target"]
        }
    },

    "crackmapexec": {
        "name": "crackmapexec",
        "description": "内网渗透工具，支持SMB、WinRM、MSSQL等协议的密码爆破和命令执行",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标IP或网段（仅允许私有IP）"
                },
                "protocol": {
                    "type": "string",
                    "enum": ["smb", "winrm", "mssql", "ssh"],
                    "description": "协议类型"
                },
                "username": {
                    "type": "string",
                    "description": "用户名"
                },
                "password": {
                    "type": "string",
                    "description": "密码"
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM Hash（Pass-the-Hash）"
                },
                "action": {
                    "type": "string",
                    "enum": ["check", "exec", "dump"],
                    "default": "check",
                    "description": "动作：检查/执行命令/导出凭据"
                },
                "command": {
                    "type": "string",
                    "description": "要执行的命令（exec模式）"
                }
            },
            "required": ["target", "protocol"]
        }
    },

    "impacket": {
        "name": "impacket",
        "description": "网络协议工具包，支持SMB、LDAP、Kerberos等协议的渗透测试",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "enum": ["psexec", "wmiexec", "smbexec", "secretsdump", "GetNPUsers"],
                    "description": "Impacket模块名称"
                },
                "target": {
                    "type": "string",
                    "description": "目标地址"
                },
                "username": {
                    "type": "string",
                    "description": "用户名"
                },
                "password": {
                    "type": "string",
                    "description": "密码"
                },
                "domain": {
                    "type": "string",
                    "description": "域名"
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM Hash"
                },
                "options": {
                    "type": "string",
                    "description": "额外选项（JSON格式）"
                }
            },
            "required": ["module", "target"]
        }
    },

    "bloodhound": {
        "name": "bloodhound",
        "description": "Active Directory攻击路径分析工具",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["collect", "analyze"],
                    "description": "动作：收集数据/分析数据"
                },
                "domain": {
                    "type": "string",
                    "description": "目标域名（collect模式）"
                },
                "username": {
                    "type": "string",
                    "description": "用户名（collect模式）"
                },
                "password": {
                    "type": "string",
                    "description": "密码（collect模式）"
                },
                "json_file": {
                    "type": "string",
                    "description": "数据文件路径（analyze模式）"
                }
            },
            "required": ["action"]
        }
    },
    "hydra": {
        "name": "hydra",
        "description": "密码爆破工具，支持多种服务协议（SSH, FTP, SMB, RDP, MySQL等）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标IP或主机名"
                },
                "service": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "smb", "rdp", "mysql", "mssql", "postgres", "telnet", "smtp", "pop3", "imap"],
                    "description": "服务协议类型"
                },
                "username": {
                    "type": "string",
                    "description": "用户名"
                },
                "username_file": {
                    "type": "string",
                    "description": "用户名字典文件路径"
                },
                "password": {
                    "type": "string",
                    "description": "密码"
                },
                "password_file": {
                    "type": "string",
                    "description": "密码字典文件路径"
                },
                "port": {
                    "type": "integer",
                    "description": "端口号（可选）"
                }
            },
            "required": ["target", "service"]
        }
    },
    "xray": {
        "name": "xray",
        "description": "长亭安全被动/主动扫描工具，支持漏洞扫描和服务探测",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "format": "uri",
                    "description": "目标URL"
                },
                "mode": {
                    "type": "string",
                    "enum": ["active", "passive", "servicescan"],
                    "default": "active",
                    "description": "扫描模式：主动扫描/被动扫描/服务扫描"
                },
                "plugin": {
                    "type": "string",
                    "description": "指定插件（可选）"
                },
                "output_file": {
                    "type": "string",
                    "description": "输出文件路径（可选）"
                }
            },
            "required": ["target_url"]
        }
    },
    "subfinder": {
        "name": "subfinder",
        "description": "子域名发现工具，快速枚举目标域名的子域名",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "目标域名"
                },
                "recursive": {
                    "type": "boolean",
                    "default": false,
                    "description": "是否递归枚举"
                },
                "threads": {
                    "type": "integer",
                    "default": 10,
                    "description": "并发线程数"
                }
            },
            "required": ["domain"]
        }
    },
    "frp": {
        "name": "frp",
        "description": "内网穿透工具，支持TCP/UDP端口映射",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "stop", "status", "create_config"],
                    "description": "操作类型"
                },
                "config_type": {
                    "type": "string",
                    "enum": ["client", "server"],
                    "default": "client",
                    "description": "配置类型：客户端/服务端"
                },
                "server_addr": {
                    "type": "string",
                    "description": "服务器地址（client模式）"
                },
                "server_port": {
                    "type": "integer",
                    "default": 7000,
                    "description": "服务器端口"
                },
                "local_ip": {
                    "type": "string",
                    "default": "127.0.0.1",
                    "description": "本地IP"
                },
                "local_port": {
                    "type": "integer",
                    "description": "本地端口"
                },
                "remote_port": {
                    "type": "integer",
                    "description": "远程端口"
                }
            },
            "required": ["action"]
        }
    },
    "ysoserial": {
        "name": "ysoserial",
        "description": "Java反序列化payload生成工具",
        "inputSchema": {
            "type": "object",
            "properties": {
                "gadget": {
                    "type": "string",
                    "description": "Gadget名称（如URLDNS, CommonsCollections1等）"
                },
                "command": {
                    "type": "string",
                    "description": "要执行的命令"
                },
                "output_format": {
                    "type": "string",
                    "default": "raw",
                    "description": "输出格式"
                }
            },
            "required": ["gadget", "command"]
        }
    },
    "jwt_tool": {
        "name": "jwt_tool",
        "description": "JWT漏洞利用工具，支持解码、伪造、破解等",
        "inputSchema": {
            "type": "object",
            "properties": {
                "jwt_token": {
                    "type": "string",
                    "description": "JWT Token"
                },
                "action": {
                    "type": "string",
                    "enum": ["decode", "verify", "crack", "inject", "none_algorithm"],
                    "default": "decode",
                    "description": "操作类型"
                },
                "key": {
                    "type": "string",
                    "description": "密钥（verify/crack模式）"
                },
                "algorithm": {
                    "type": "string",
                    "description": "算法（可选）"
                },
                "inject_payload": {
                    "type": "string",
                    "description": "注入payload（inject模式）"
                }
            },
            "required": ["jwt_token"]
        }
    },
    "ssrfmap": {
        "name": "ssrfmap",
        "description": "SSRF漏洞利用框架",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "format": "uri",
                    "description": "目标URL"
                },
                "param": {
                    "type": "string",
                    "description": "测试参数名"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP方法"
                },
                "data": {
                    "type": "string",
                    "description": "POST数据（POST模式）"
                },
                "modules": {
                    "type": "string",
                    "default": "all",
                    "description": "测试模块（如redis,mysql,all等）"
                }
            },
            "required": ["target_url", "param"]
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

    # 参数验证
    is_valid, error = validate_target(target)
    if not is_valid:
        return {"success": False, "error": error}

    is_valid, error = validate_ports(ports)
    if not is_valid:
        return {"success": False, "error": error}

    # 扫描类型白名单
    if scan_type not in ["quick", "full", "service"]:
        return {"success": False, "error": f"无效的扫描类型: {scan_type}"}

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

    # 参数验证 - nuclei接受URL或IP
    if target.startswith(("http://", "https://")):
        is_valid, error = validate_url_for_ssrf(target)
        if not is_valid:
            return {"success": False, "error": error}
    else:
        is_valid, error = validate_target(target)
        if not is_valid:
            return {"success": False, "error": error}

    # severity白名单
    if severity and severity not in ["critical", "high", "medium", "low", "info"]:
        return {"success": False, "error": f"无效的严重级别: {severity}"}

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

    # 参数验证
    is_valid, error = validate_target(target)
    if not is_valid:
        return {"success": False, "error": error}

    if ports:
        is_valid, error = validate_ports(ports)
        if not is_valid:
            return {"success": False, "error": error}

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
    """fscan执行 - 内网扫描工具，允许私有IP"""
    fscan_path = shutil.which("fscan") or shutil.which("fscan.exe") or "./fscan"

    # 参数验证 - fscan用于内网，允许私有IP
    is_valid, error = validate_target(target)
    if not is_valid:
        return {"success": False, "error": error}

    if ports:
        is_valid, error = validate_ports(ports)
        if not is_valid:
            return {"success": False, "error": error}

    cmd = [fscan_path, "-h", target]
    if ports:
        cmd.extend(["-p", ports])

    return await run_command(cmd)


async def sqlmap_handler(target_url: str, level: int = 1, action: str = "detect") -> Dict:
    """sqlmap执行"""
    sqlmap_path = shutil.which("sqlmap") or "sqlmap.py"

    # SSRF防护 - sqlmap可能向任意URL发送请求
    is_valid, error = validate_url_for_ssrf(target_url)
    if not is_valid:
        return {"success": False, "error": error}

    # level范围验证
    if not 1 <= level <= 5:
        return {"success": False, "error": f"level必须在1-5之间: {level}"}

    # action白名单
    if action not in ["detect", "dbs", "tables", "dump"]:
        return {"success": False, "error": f"无效的action: {action}"}

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


async def ffuf_handler(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    mode: str = "dir",
    extensions: str = None
) -> Dict:
    """ffuf执行 - 快速Web模糊测试"""
    if not shutil.which("ffuf"):
        return {"success": False, "error": "ffuf未安装"}

    # SSRF防护
    is_valid, error = validate_url_for_ssrf(target_url)
    if not is_valid:
        return {"success": False, "error": error}

    # mode白名单
    if mode not in ["dir", "fuzz", "param"]:
        return {"success": False, "error": f"无效的mode: {mode}"}

    # 检查URL包含FUZZ关键字
    if "FUZZ" not in target_url:
        if mode == "dir":
            target_url = target_url.rstrip('/') + "/FUZZ"
        elif mode == "param":
            # 查找参数位置
            if "?" in target_url:
                target_url = target_url + "&FUZZ=test"
            else:
                target_url = target_url + "?FUZZ=test"

    cmd = [
        "ffuf", "-u", target_url,
        "-w", wordlist,
        "-silent", "-json"
    ]

    if extensions:
        cmd.extend(["-e", extensions])

    result = await run_command(cmd, timeout=300)
    if result["success"]:
        # 解析结果
        findings = []
        for line in result["stdout"].strip().split('\n'):
            if line.startswith('{'):
                try:
                    findings.append(json.loads(line))
                except:
                    pass
        result["findings"] = findings
    return result


async def dirsearch_handler(
    target_url: str,
    extensions: str = "php,html,js",
    wordlist: str = None,
    recursive: bool = False
) -> Dict:
    """dirsearch执行 - 高级目录扫描"""
    if not shutil.which("dirsearch"):
        return {"success": False, "error": "dirsearch未安装"}

    # SSRF防护
    is_valid, error = validate_url_for_ssrf(target_url)
    if not is_valid:
        return {"success": False, "error": error}

    cmd = [
        "dirsearch", "-u", target_url,
        "-e", extensions,
        "--format=json"
    ]

    if wordlist:
        cmd.extend(["-w", wordlist])

    if recursive:
        cmd.append("-r")

    result = await run_command(cmd, timeout=300)
    if result["success"]:
        # 解析结果
        findings = []
        try:
            data = json.loads(result["stdout"])
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                findings = data.get("results", [])
        except:
            pass
        result["findings"] = findings
    return result


async def gobuster_handler(
    target: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = None,
    threads: int = 10
) -> Dict:
    """gobuster执行 - 多协议爆破工具"""
    if not shutil.which("gobuster"):
        return {"success": False, "error": "gobuster未安装"}

    # 参数验证
    is_valid, error = validate_target(target)
    if not is_valid:
        return {"success": False, "error": error}

    # mode白名单
    if mode not in ["dir", "dns", "s3"]:
        return {"success": False, "error": f"无效的mode: {mode}"}

    # threads范围验证
    if not 1 <= threads <= 100:
        return {"success": False, "error": f"threads必须在1-100之间: {threads}"}

    cmd = ["gobuster"]

    if mode == "dir":
        # SSRF防护 - 目录模式需要URL
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        is_valid, error = validate_url_for_ssrf(target)
        if not is_valid:
            return {"success": False, "error": error}

        cmd.extend(["dir", "-u", target, "-w", wordlist])
        if extensions:
            cmd.extend(["-x", extensions])
        cmd.extend(["-t", str(threads), "-q"])

    elif mode == "dns":
        cmd.extend(["dns", "-d", target, "-w", wordlist, "-t", str(threads), "-q"])

    elif mode == "s3":
        cmd.extend(["s3", "-w", wordlist, "-t", str(threads), "-q"])

    result = await run_command(cmd, timeout=300)
    if result["success"]:
        # 解析结果
        findings = []
        for line in result["stdout"].strip().split('\n'):
            if line and not line.startswith('['):
                findings.append(line.strip())
        result["findings"] = findings
    return result


async def whatweb_handler(
    target: str,
    aggression: int = 1,
    verbose: bool = False
) -> Dict:
    """whatweb执行 - 技术栈识别"""
    if not shutil.which("whatweb"):
        return {"success": False, "error": "whatweb未安装"}

    # 参数验证
    if target.startswith(("http://", "https://")):
        is_valid, error = validate_url_for_ssrf(target)
    else:
        is_valid, error = validate_target(target)

    if not is_valid:
        return {"success": False, "error": error}

    # aggression范围验证
    if not 1 <= aggression <= 4:
        return {"success": False, "error": f"aggression必须在1-4之间: {aggression}"}

    cmd = ["whatweb", target]

    if aggression > 1:
        cmd.append(f"-{'a' * aggression}")

    if verbose:
        cmd.append("-v")

    cmd.append("--color=never")

    result = await run_command(cmd, timeout=180)
    if result["success"]:
        # 解析识别的技术栈
        techs = []
        output = result["stdout"].strip()
        # whatweb格式: http://example.com [200 OK] nginx, PHP, jQuery
        if '[' in output:
            parts = output.split(']', 1)
            if len(parts) > 1:
                techs = [t.strip() for t in parts[1].split(',') if t.strip()]
        result["technologies"] = techs
    return result


async def crackmapexec_handler(
    target: str,
    protocol: str,
    username: str = None,
    password: str = None,
    hash: str = None,
    action: str = "check",
    command: str = None
) -> Dict:
    """crackmapexec执行 - 内网渗透工具（仅允许私有IP）"""
    if not shutil.which("crackmapexec"):
        return {"success": False, "error": "crackmapexec未安装"}

    # 安全检查：仅允许私有IP
    try:
        ip = ipaddress.ip_address(target.split('/')[0])
        if not ip.is_private:
            return {"success": False, "error": "安全限制：crackmapexec仅允许扫描私有IP地址"}
    except ValueError:
        # 可能是网段格式
        try:
            network = ipaddress.ip_network(target, strict=False)
            if not all(ip.is_private for ip in network.hosts()):
                return {"success": False, "error": "安全限制：crackmapexec仅允许扫描私有IP网段"}
        except ValueError:
            return {"success": False, "error": f"无效的目标地址: {target}"}

    # protocol白名单
    if protocol not in ["smb", "winrm", "mssql", "ssh"]:
        return {"success": False, "error": f"无效的protocol: {protocol}"}

    # action白名单
    if action not in ["check", "exec", "dump"]:
        return {"success": False, "error": f"无效的action: {action}"}

    cmd = ["crackmapexec", protocol, target]

    # 认证参数
    if username and password:
        cmd.extend(["-u", username, "-p", password])
    elif username and hash:
        cmd.extend(["-u", username, "-H", hash])

    # 动作参数
    if action == "exec" and command:
        cmd.extend(["-x", command])
    elif action == "dump":
        if protocol == "smb":
            cmd.append("--sam")
        elif protocol == "mssql":
            cmd.append("-M mssql_priv")

    result = await run_command(cmd, timeout=600)

    # 解析结果
    if result["success"]:
        hosts = []
        for line in result["stdout"].split('\n'):
            if protocol.upper() in line:
                hosts.append(line.strip())
        result["hosts"] = hosts
    return result


async def impacket_handler(
    module: str,
    target: str,
    username: str = None,
    password: str = None,
    domain: str = None,
    hash: str = None,
    options: str = None
) -> Dict:
    """impacket执行 - 网络协议工具包"""
    # 检查impacket安装
    impacket_path = shutil.which(module)
    if not impacket_path:
        # 尝试Python模块方式
        impacket_path = "python"
        module_check = await run_command([impacket_path, "-m", "impacket.examples." + module], timeout=5)
        if "No module" in module_check.get("stderr", ""):
            return {"success": False, "error": f"impacket.{module}未安装"}

    # module白名单
    allowed_modules = ["psexec", "wmiexec", "smbexec", "secretsdump", "GetNPUsers"]
    if module not in allowed_modules:
        return {"success": False, "error": f"不支持的模块: {module}。允许的模块: {', '.join(allowed_modules)}"}

    # 目标格式验证
    if not target:
        return {"success": False, "error": "目标地址不能为空"}

    cmd = [impacket_path] if impacket_path.endswith(".py") else [impacket_path]

    # 构造认证字符串
    if username:
        auth_str = username
        if domain:
            auth_str = f"{domain}/{username}"
        if password:
            auth_str += f":{password}"
        elif hash:
            auth_str += f" -hashes :{hash}"

        cmd.append(auth_str)

    cmd.append(target)

    # 额外选项
    if options:
        try:
            opts = json.loads(options)
            for k, v in opts.items():
                cmd.extend([f"-{k}", str(v)])
        except:
            pass

    result = await run_command(cmd, timeout=600)
    return result


async def bloodhound_handler(
    action: str,
    domain: str = None,
    username: str = None,
    password: str = None,
    json_file: str = None
) -> Dict:
    """bloodhound执行 - AD攻击路径分析"""
    # action白名单
    if action not in ["collect", "analyze"]:
        return {"success": False, "error": f"无效的action: {action}"}

    if action == "collect":
        # 数据收集模式
        bloodhound_python = shutil.which("bloodhound-python")
        if not bloodhound_python:
            return {"success": False, "error": "bloodhound-python未安装"}

        if not all([domain, username, password]):
            return {"success": False, "error": "collect模式需要domain、username、password参数"}

        cmd = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-p", password,
            "--method",
            "-c", "all",
            "-v"
        ]

        result = await run_command(cmd, timeout=1800)  # 30分钟超时
        if result["success"]:
            result["output_dir"] = f"{domain}_bloodhound_data"

    else:
        # analyze模式 - 查询Neo4j数据库
        # 注意：需要BloodHound GUI运行并连接Neo4j
        return {"success": False, "error": "analyze模式需要BloodHound GUI运行，请使用Cypher查询Neo4j数据库"}

    return result


async def hydra_handler(
    target: str,
    service: str,
    username: str = None,
    username_file: str = None,
    password: str = None,
    password_file: str = None,
    port: int = None
) -> Dict:
    """hydra执行 - 密码爆破工具"""
    if not shutil.which("hydra"):
        return {"success": False, "error": "hydra未安装"}

    # 目标验证
    is_valid, error = validate_target(target)
    if not is_valid:
        return {"success": False, "error": error}

    # service白名单
    allowed_services = ["ssh", "ftp", "smb", "rdp", "mysql", "mssql", "postgres", "telnet", "smtp", "pop3", "imap"]
    if service not in allowed_services:
        return {"success": False, "error": f"不支持的service: {service}。支持: {', '.join(allowed_services)}"}

    # 至少需要用户名或用户名字典
    if not username and not username_file:
        return {"success": False, "error": "需要username或username_file参数"}

    # 至少需要密码或密码字典
    if not password and not password_file:
        return {"success": False, "error": "需要password或password_file参数"}

    cmd = ["hydra", "-f", "-q"]  # -f: 找到第一个有效密码后停止, -q: 安静模式

    # 用户名或用户名字典
    if username_file:
        cmd.extend(["-L", username_file])
    else:
        cmd.extend(["-l", username])

    # 密码或密码字典
    if password_file:
        cmd.extend(["-P", password_file])
    else:
        cmd.extend(["-p", password])

    # 端口
    if port:
        cmd.extend(["-s", str(port)])

    # 目标和服务
    cmd.append(f"{service}://{target}")

    result = await run_command(cmd, timeout=600)

    if result["success"]:
        # 解析hydra输出
        output = result.get("output", "")
        credentials = []

        # 提取成功爆破的凭据
        for line in output.split('\n'):
            if 'login:' in line.lower() and 'password:' in line.lower():
                # 格式: [22][ssh] login: admin   password: admin123
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'login:':
                        username = parts[i+1] if i+1 < len(parts) else ''
                    if part == 'password:':
                        password = parts[i+1] if i+1 < len(parts) else ''

                if username and password:
                    credentials.append({
                        "service": service,
                        "username": username,
                        "password": password
                    })

        result["credentials"] = credentials
        result["found"] = len(credentials) > 0

    return result


# ============================================
# P0级工具 - 核心补充
# ============================================

async def xray_handler(
    target_url: str,
    mode: str = "active",
    plugin: str = None,
    output_file: str = None
) -> Dict:
    """xray执行 - 长亭被动/主动扫描工具"""
    xray_path = shutil.which("xray") or "/usr/local/bin/xray"
    if not os.path.exists(xray_path):
        return {"success": False, "error": "xray未安装"}

    # SSRF防护
    is_valid, error = validate_url_for_ssrf(target_url)
    if not is_valid:
        return {"success": False, "error": error}

    # mode白名单
    if mode not in ["active", "passive", "servicescan"]:
        return {"success": False, "error": f"无效的mode: {mode}"}

    if mode == "active":
        # 主动扫描
        cmd = [xray_path, "webscan", "--basic-crawler", target_url, "--json"]
    elif mode == "servicescan":
        # 服务扫描
        cmd = [xray_path, "servicescan", "--target", target_url]
    else:
        return {"success": False, "error": "被动扫描需要启动xray服务，请使用: xray webscan --listen 127.0.0.1:7777"}

    result = await run_command(cmd, timeout=600)

    if result["success"]:
        output = result.get("output", "")
        vulns = []

        # 解析JSON输出
        try:
            for line in output.split('\n'):
                if line.strip().startswith('{'):
                    vuln = json.loads(line)
                    vulns.append({
                        "plugin": vuln.get("plugin", ""),
                        "url": vuln.get("target", {}).get("url", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "description": vuln.get("description", "")
                    })
        except:
            pass

        result["vulnerabilities"] = vulns
        result["vuln_count"] = len(vulns)

    return result


async def subfinder_handler(
    domain: str,
    recursive: bool = False,
    threads: int = 10
) -> Dict:
    """subfinder执行 - 子域名发现工具"""
    subfinder_path = shutil.which("subfinder") or "/usr/local/bin/subfinder"
    if not os.path.exists(subfinder_path):
        return {"success": False, "error": "subfinder未安装"}

    # 域名验证
    if not domain or len(domain) > 253:
        return {"success": False, "error": "无效的域名"}

    cmd = [
        subfinder_path,
        "-d", domain,
        "-silent",
        "-json",
        "-t", str(threads)
    ]

    if recursive:
        cmd.append("-recursive")

    result = await run_command(cmd, timeout=300)

    if result["success"]:
        output = result.get("output", "")
        subdomains = []

        for line in output.split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("host", ""))
                except:
                    if line.strip() and '.' in line:
                        subdomains.append(line.strip())

        result["subdomains"] = list(set(subdomains))
        result["count"] = len(result["subdomains"])

    return result


async def frp_handler(
    action: str,
    config_type: str = "client",
    server_addr: str = None,
    server_port: int = 7000,
    local_ip: str = "127.0.0.1",
    local_port: int = None,
    remote_port: int = None
) -> Dict:
    """frp执行 - 内网穿透工具"""
    frpc_path = shutil.which("frpc") or "/opt/frp/frpc"
    frps_path = shutil.which("frps") or "/opt/frp/frps"

    # action白名单
    if action not in ["start", "stop", "status", "create_config"]:
        return {"success": False, "error": f"无效的action: {action}"}

    if action == "create_config":
        # 生成配置文件
        config = {
            "common": {
                "server_addr": server_addr,
                "server_port": server_port
            }
        }

        if config_type == "client" and local_port and remote_port:
            config["tcp_tunnel"] = {
                "type": "tcp",
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port
            }

        return {
            "success": True,
            "config": config,
            "config_path": f"/tmp/frp_{config_type}.ini"
        }

    elif action == "start":
        if config_type == "client":
            if not os.path.exists(frpc_path):
                return {"success": False, "error": "frpc未安装"}
            cmd = [frpc_path, "-c", f"/tmp/frp_client.ini"]
        else:
            if not os.path.exists(frps_path):
                return {"success": False, "error": "frps未安装"}
            cmd = [frps_path, "-c", f"/tmp/frp_server.ini"]

        result = await run_command(cmd, timeout=10)
        result["message"] = f"frp {config_type}启动成功"
        return result

    elif action == "stop":
        # 停止frp进程
        stop_cmd = "pkill -f frpc" if config_type == "client" else "pkill -f frps"
        result = await run_command(stop_cmd.split(), timeout=5)
        result["message"] = f"frp {config_type}已停止"
        return result

    elif action == "status":
        # 检查frp进程状态
        check_cmd = "pgrep -f frpc" if config_type == "client" else "pgrep -f frps"
        result = await run_command(check_cmd.split(), timeout=5)
        result["running"] = result["success"]
        return result

    return {"success": False, "error": "未知操作"}


# ============================================
# P1级工具 - 高优先级补充
# ============================================

async def ysoserial_handler(
    gadget: str,
    command: str,
    output_format: str = "raw"
) -> Dict:
    """ysoserial执行 - Java反序列化payload生成"""
    ysoserial_path = "/app/thirdparty/ysoserial.jar"
    if not os.path.exists(ysoserial_path):
        return {"success": False, "error": "ysoserial未安装"}

    # gadget白名单（常用）
    allowed_gadgets = [
        "URLDNS", "CommonsBeanutils1", "CommonsCollections1", "CommonsCollections2",
        "CommonsCollections3", "CommonsCollections4", "CommonsCollections5",
        "CommonsCollections6", "CommonsCollections7", "JRMPClient", "JRMPListener",
        "Jdk7u21", "Jdk8u20", "Spring1", "Spring2", "Hibernate1"
    ]

    if gadget not in allowed_gadgets:
        return {"success": False, "error": f"不支持的gadget: {gadget}。常用: {', '.join(allowed_gadgets[:5])}"}

    cmd = ["java", "-jar", ysoserial_path, gadget, command]

    result = await run_command(cmd, timeout=30)

    if result["success"]:
        payload = result.get("output", "")
        result["payload"] = payload
        result["payload_size"] = len(payload)
        result["gadget"] = gadget
        result["command"] = command

    return result


async def jwt_tool_handler(
    jwt_token: str,
    action: str = "decode",
    key: str = None,
    algorithm: str = None,
    inject_payload: str = None
) -> Dict:
    """jwt_tool执行 - JWT漏洞利用工具"""
    jwt_tool_path = "/app/thirdparty/jwt_tool/jwt_tool.py"
    if not os.path.exists(jwt_tool_path):
        return {"success": False, "error": "jwt_tool未安装"}

    # action白名单
    if action not in ["decode", "verify", "crack", "inject", "none_algorithm"]:
        return {"success": False, "error": f"无效的action: {action}"}

    cmd = ["python3", jwt_tool_path, jwt_token]

    if action == "decode":
        cmd.append("-d")
    elif action == "verify" and key:
        cmd.extend(["-k", key])
    elif action == "crack":
        cmd.append("-C")  # Crack模式
        if key:
            cmd.extend(["-k", key])
    elif action == "inject" and inject_payload:
        cmd.extend(["-I", "-pc", inject_payload])  # Inject claim
    elif action == "none_algorithm":
        cmd.append("-X")  # Exploit: None algorithm

    result = await run_command(cmd, timeout=60)

    if result["success"]:
        output = result.get("output", "")
        result["analysis"] = output

        # 解析JWT（简化）
        if action == "decode":
            parts = jwt_token.split('.')
            if len(parts) == 3:
                try:
                    import base64
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                    result["header"] = header
                    result["payload"] = payload
                except:
                    pass

    return result


async def ssrfmap_handler(
    target_url: str,
    param: str,
    method: str = "GET",
    data: str = None,
    modules: str = "all"
) -> Dict:
    """SSRFmap执行 - SSRF漏洞利用框架"""
    ssrfmap_path = "/app/thirdparty/SSRFmap/ssrfmap.py"
    if not os.path.exists(ssrfmap_path):
        return {"success": False, "error": "SSRFmap未安装"}

    # SSRF防护（SSRFmap是测试工具，需要允许私有IP）
    # 但需要确保URL格式正确
    if not target_url.startswith(("http://", "https://")):
        return {"success": False, "error": "URL必须以http://或https://开头"}

    cmd = [
        "python3", ssrfmap_path,
        "-r", target_url,
        "-p", param,
        "-m", modules
    ]

    if method.upper() == "POST" and data:
        cmd.extend(["--method", "POST", "--data", data])

    result = await run_command(cmd, timeout=300)

    if result["success"]:
        output = result.get("output", "")
        result["findings"] = output

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
    "ffuf": ffuf_handler,
    "dirsearch": dirsearch_handler,
    "gobuster": gobuster_handler,
    "whatweb": whatweb_handler,
    "crackmapexec": crackmapexec_handler,
    "impacket": impacket_handler,
    "bloodhound": bloodhound_handler,
    "hydra": hydra_handler,
    # P0级新增
    "xray": xray_handler,
    "subfinder": subfinder_handler,
    "frp": frp_handler,
    # P1级新增
    "ysoserial": ysoserial_handler,
    "jwt_tool": jwt_tool_handler,
    "ssrfmap": ssrfmap_handler,
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