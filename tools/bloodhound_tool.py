# tools/bloodhound_tool.py
"""
BloodHound Tool - AD域分析工具适配
适配自 Zen-Ai-Pentest 的 bloodhound_integration.py

功能:
- AD域信息收集
- 攻击路径分析
- 权限关系可视化

CTF场景优化:
- 快速数据采集
- 自动化分析
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


class BloodHoundTool(CommandLineTool):
    """
    BloodHound AD域分析工具封装
    """

    def __init__(self):
        # 检测 bloodhound-python 是否可用
        self.executable = shutil.which("bloodhound-python")

        if self.executable:
            self.cmd_path = self.executable
        else:
            self.cmd_path = "bloodhound-python"

        super().__init__(self.cmd_path)
        self.timeout = 600

    def name(self) -> str:
        return "bloodhound"

    def description(self) -> str:
        return "AD域攻击路径分析工具，发现权限提升路径。"

    def supported_vulns(self) -> list:
        return [
            "AD Enumeration",
            "Kerberos Attack",
            "Privilege Escalation",
            "Lateral Movement",
            "Domain Trust"
        ]

    def check_available(self) -> bool:
        if self.executable:
            return True
        try:
            result = subprocess.run(
                ["bloodhound-python", "--help"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {
                "type": "str",
                "description": "目标域名 (如 corp.local)",
                "required": True
            },
            "dc": {
                "type": "str",
                "description": "域控制器IP",
                "required": True
            },
            "username": {
                "type": "str",
                "description": "用户名",
                "required": True
            },
            "password": {
                "type": "str",
                "description": "密码",
                "required": False,
                "default": None
            },
            "hash": {
                "type": "str",
                "description": "NTLM哈希",
                "required": False,
                "default": None
            },
            "collection": {
                "type": "str",
                "description": "收集方法: 'all', 'group', 'localadmin', 'session', 'trust', 'acl', 'container'",
                "required": False,
                "default": "all"
            },
            "output_dir": {
                "type": "str",
                "description": "输出目录",
                "required": False,
                "default": "data/bloodhound"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        domain = params.get("domain")
        dc = params.get("dc") or target
        username = params.get("username")
        password = params.get("password")
        hash_val = params.get("hash")
        collection = params.get("collection", "all")
        output_dir = params.get("output_dir", "data/bloodhound")

        if not all([domain, dc, username]):
            return {"error": "必须提供 domain, dc, username", "success": False}

        if not password and not hash_val:
            return {"error": "必须提供 password 或 hash", "success": False}

        cmd = [
            self.cmd_path,
            "-d", domain,
            "-dc", dc,
            "-u", username,
            "-c", collection,
            "--outputfolder", output_dir
        ]

        if password:
            cmd.extend(["-p", password])
        elif hash_val:
            cmd.extend(["--hash", hash_val])

        try:
            result = self._run_command(cmd, timeout=self.timeout)
            return {
                "success": result.get("success", False),
                "domain": domain,
                "output_dir": output_dir,
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", "")
            }
        except Exception as e:
            return {"success": False, "error": str(e)}