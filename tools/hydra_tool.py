# tools/hydra_tool.py
"""
Hydra Tool - 密码爆破工具适配

功能:
- 多协议密码爆破
- 并行攻击
- 字典攻击

CTF场景优化:
- 快速模式
- 常用协议支持
"""
import re
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class HydraTool(CommandLineTool):
    """Hydra 密码爆破工具封装"""

    SUPPORTED_PROTOCOLS = [
        "ftp", "ssh", "telnet", "http-get", "http-post", "https-get",
        "mysql", "mssql", "oracle", "postgres", "redis", "smb",
        "smtp", "pop3", "imap", "ldap", "rdp", "vnc"
    ]

    def __init__(self):
        self.executable = shutil.which("hydra")
        self.cmd_path = self.executable or "hydra"
        super().__init__(self.cmd_path)
        self.timeout = 600

    def name(self) -> str:
        return "hydra"

    def description(self) -> str:
        return "多协议密码爆破工具，支持SSH/FTP/HTTP/SMB等协议。"

    def supported_vulns(self) -> list:
        return ["Password Brute Force", "Credential Stuffing", "Dictionary Attack"]

    def capability_statement(self) -> str:
        return "密码爆破工具。支持SSH/FTP/HTTP/MySQL等多种协议。适合：登录表单、开放服务端口、弱口令检测。"

    def check_available(self) -> bool:
        if self.executable:
            return True
        try:
            subprocess.run(["hydra", "-h"], capture_output=True, timeout=5)
            return True
        except:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标IP或主机名",
                "required": True
            },
            "protocol": {
                "type": "str",
                "description": f"协议: {', '.join(self.SUPPORTED_PROTOCOLS[:10])}...",
                "required": True
            },
            "port": {
                "type": "int",
                "description": "目标端口",
                "required": False,
                "default": None
            },
            "username": {
                "type": "str",
                "description": "用户名或用户名字典文件 (前缀-L)",
                "required": False,
                "default": None
            },
            "password": {
                "type": "str",
                "description": "密码或密码字典文件 (前缀-P)",
                "required": False,
                "default": None
            },
            "user_pass_file": {
                "type": "str",
                "description": "用户名:密码组合文件 (-C)",
                "required": False,
                "default": None
            },
            "threads": {
                "type": "int",
                "description": "线程数",
                "required": False,
                "default": 4
            },
            "verbose": {
                "type": "bool",
                "description": "详细输出",
                "required": False,
                "default": False
            },
            "extra_options": {
                "type": "str",
                "description": "协议特定选项 (如 http-post-form 的路径)",
                "required": False,
                "default": None
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        target = params.get("target") or target
        protocol = params.get("protocol")
        port = params.get("port")
        username = params.get("username")
        password = params.get("password")
        user_pass_file = params.get("user_pass_file")
        threads = params.get("threads", 4)
        verbose = params.get("verbose", False)
        extra_options = params.get("extra_options")

        if not all([target, protocol]):
            return {"error": "必须提供 target 和 protocol", "success": False}

        if not username and not user_pass_file:
            return {"error": "必须提供 username 或 user_pass_file", "success": False}

        if not password and not user_pass_file:
            return {"error": "必须提供 password 或 user_pass_file", "success": False}

        cmd = [self.cmd_path]

        # 线程数
        cmd.extend(["-t", str(threads)])

        # 用户名
        if username:
            if username.startswith("/"):
                cmd.extend(["-L", username])
            else:
                cmd.extend(["-l", username])

        # 密码
        if password:
            if password.startswith("/"):
                cmd.extend(["-P", password])
            else:
                cmd.extend(["-p", password])

        # 用户名:密码文件
        if user_pass_file:
            cmd.extend(["-C", user_pass_file])

        # 详细输出
        if verbose:
            cmd.append("-V")

        # 目标
        if port:
            cmd.extend(["-s", str(port)])

        # 协议和目标
        if extra_options:
            cmd.append(f"{protocol}://{target}{extra_options}")
        else:
            cmd.append(f"{protocol}://{target}")

        try:
            result = self._run_command(cmd, timeout=self.timeout)
            stdout = result.get("stdout", "")

            # 解析结果
            credentials = self._parse_output(stdout)

            return {
                "success": len(credentials) > 0,
                "target": target,
                "protocol": protocol,
                "credentials_found": credentials,
                "stdout": stdout,
                "stderr": result.get("stderr", "")
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_output(self, output: str) -> List[Dict]:
        """解析hydra输出"""
        credentials = []

        # 匹配成功的凭据行
        # 格式: [22][ssh] host: 192.168.1.1   login: admin   password: admin123
        pattern = re.compile(
            r'\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)'
        )

        for match in pattern.finditer(output):
            credentials.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "host": match.group(3),
                "username": match.group(4),
                "password": match.group(5)
            })

        return credentials