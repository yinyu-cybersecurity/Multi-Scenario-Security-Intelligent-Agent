# tools/impacket_tool.py
"""
Impacket Tool - Python渗透脚本集适配

功能:
- SMB操作 (psexec, wmiexec, smbexec等)
- Kerberos攻击
- LDAP操作
- 秘密转储

CTF场景优化:
- 快速凭据利用
- 自动化操作
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


class ImpacketTool(CommandLineTool):
    """Impacket 渗透脚本集封装"""

    # 常用脚本
    SCRIPTS = {
        "psexec": "psexec.py",
        "wmiexec": "wmiexec.py",
        "smbexec": "smbexec.py",
        "atexec": "atexec.py",
        "dcomexec": "dcomexec.py",
        "secretsdump": "secretsdump.py",
        "GetNPUsers": "GetNPUsers.py",
        "GetUserSPNs": "GetUserSPNs.py",
        "smbclient": "smbclient.py",
        "lookupsid": "lookupsid.py",
        "ntlmrelayx": "ntlmrelayx.py",
        "mssqlclient": "mssqlclient.py",
    }

    def __init__(self):
        # 检测 impacket 脚本位置
        self.scripts_dir = None

        # 尝试查找脚本目录
        possible_paths = [
            "/usr/share/doc/python3-impacket/examples",
            "/usr/local/share/impacket",
            "/root/.local/pipx/venvs/impacket/lib/python*/site-packages/impacket/examples",
            "/opt/impacket/examples",
        ]

        import glob
        for path in possible_paths:
            matches = glob.glob(path)
            if matches:
                self.scripts_dir = matches[0]
                break

        self.cmd_path = "python3"  # 使用 python3 执行脚本
        super().__init__(self.cmd_path)
        self.timeout = 600

    def name(self) -> str:
        return "impacket"

    def description(self) -> str:
        return "Impacket渗透脚本集，支持SMB/Kerberos/LDAP等协议操作。"

    def supported_vulns(self) -> list:
        return [
            "SMB Exploitation",
            "Kerberos Attack",
            "Credential Dumping",
            "Lateral Movement",
            "Pass the Hash"
        ]

    def check_available(self) -> bool:
        try:
            # 检查是否有可用的脚本
            result = subprocess.run(
                ["which", "psexec.py"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0 or self.scripts_dir is not None
        except:
            return self.scripts_dir is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "script": {
                "type": "str",
                "description": f"脚本名称: {', '.join(self.SCRIPTS.keys())}",
                "required": True
            },
            "target": {
                "type": "str",
                "description": "目标IP或主机名",
                "required": True
            },
            "username": {
                "type": "str",
                "description": "用户名",
                "required": True
            },
            "password": {
                "type": "str",
                "description": "密码或NTLM哈希",
                "required": False,
                "default": None
            },
            "domain": {
                "type": "str",
                "description": "域名",
                "required": False,
                "default": None
            },
            "hash": {
                "type": "str",
                "description": "NTLM哈希 (LMHASH:NTHASH)",
                "required": False,
                "default": None
            },
            "command": {
                "type": "str",
                "description": "要执行的命令 (用于psexec等)",
                "required": False,
                "default": None
            },
            "options": {
                "type": "list",
                "description": "额外命令行选项",
                "required": False,
                "default": []
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        script = params.get("script")
        target = params.get("target") or target
        username = params.get("username")
        password = params.get("password")
        domain = params.get("domain", "")
        hash_val = params.get("hash")
        command = params.get("command")
        options = params.get("options", [])

        if not all([script, target, username]):
            return {"error": "必须提供 script, target, username", "success": False}

        if script not in self.SCRIPTS:
            return {"error": f"未知脚本: {script}. 可用: {list(self.SCRIPTS.keys())}", "success": False}

        # 查找脚本路径
        script_name = self.SCRIPTS[script]

        # 尝试多种方式找到脚本
        script_path = None

        # 1. 直接在PATH中查找
        in_path = shutil.which(script_name)
        if in_path:
            script_path = in_path

        # 2. 在脚本目录中查找
        if not script_path and self.scripts_dir:
            import os
            candidate = os.path.join(self.scripts_dir, script_name)
            if os.path.exists(candidate):
                script_path = candidate

        if not script_path:
            return {"error": f"找不到脚本: {script_name}", "success": False}

        # 构建命令
        cmd = [self.cmd_path, script_path]

        # 认证参数
        if domain:
            auth = f"{domain}/{username}"
        else:
            auth = username

        if hash_val:
            cmd.extend(["-hashes", hash_val])
            cmd.append(f"{auth}@{target}")
        else:
            cmd.append(f"{auth}:{password}@{target}") if password else cmd.append(f"{auth}@{target}")

        # 命令参数
        if command:
            cmd.append(command)

        # 额外选项
        cmd.extend(options)

        try:
            result = self._run_command(cmd, timeout=self.timeout)
            return {
                "success": result.get("success", False),
                "script": script,
                "target": target,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", "")
            }

        except Exception as e:
            return {"success": False, "error": str(e)}