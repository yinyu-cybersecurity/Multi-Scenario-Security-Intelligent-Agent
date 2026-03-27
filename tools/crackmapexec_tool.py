# tools/crackmapexec_tool.py
"""
CrackMapExec Tool - 内网渗透工具适配
适配自 Zen-Ai-Pentest 的 crackmapexec_integration.py

功能:
- SMB枚举
- LDAP枚举
- WinRM执行
- 密码喷洒
- 横向移动检测

CTF场景优化:
- 快速枚举模式
- 自动凭据测试
- 会话管理
"""
import os
import re
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class CrackMapExecTool(CommandLineTool):
    """
    CrackMapExec 内网渗透工具封装

    重要：此工具通常需要凭据才能发挥最大作用
    - 凭据测试：需要 username + password/hash
    - 枚举模式：可以无凭据执行基础枚举

    CTF场景特点:
    - 快速凭据测试
    - 自动化枚举
    - 支持多种协议
    """

    # 前置条件声明
    REQUIRES_CREDENTIALS = False  # 可以无凭据执行基础枚举
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "internal"  # 内网渗透工具

    # 凭据可增强功能
    CREDENTIAL_ENHANCED = True

    def __init__(self):
        # 检测 crackmapexec 是否可用
        # 优先检查 pipx 安装路径
        pipx_path = "/root/.local/bin/crackmapexec"
        pipx_cme_path = "/root/.local/bin/cme"

        if os.path.exists(pipx_path):
            self.executable = pipx_path
        elif os.path.exists(pipx_cme_path):
            self.executable = pipx_cme_path
        else:
            self.executable = shutil.which("crackmapexec") or shutil.which("cme")

        if self.executable:
            self.cmd_path = self.executable
        else:
            # 尝试 pip 安装的路径
            self.cmd_path = "crackmapexec"

        super().__init__(self.cmd_path)
        self.timeout = 300  # 5分钟超时

    def name(self) -> str:
        return "crackmapexec"

    def description(self) -> str:
        return "内网渗透工具，支持SMB/LDAP/WinRM/MSSQL等协议的枚举和凭据测试。"

    def supported_vulns(self) -> list:
        return [
            "SMB Enumeration",
            "LDAP Enumeration",
            "Credential Testing",
            "Password Spraying",
            "Session Enumeration",
            "Lateral Movement"
        ]

    def check_available(self) -> bool:
        """检查 crackmapexec 是否可用"""
        if self.executable:
            return True
        try:
            result = subprocess.run(
                ["crackmapexec", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标IP、主机名或CIDR网络 (如 192.168.1.1, 10.10.10.0/24)",
                "required": True
            },
            "protocol": {
                "type": "str",
                "description": "协议类型: 'smb', 'ldap', 'winrm', 'mssql', 'ssh', 'ftp'",
                "required": False,
                "default": "smb"
            },
            "username": {
                "type": "str",
                "description": "用户名或用户名文件路径",
                "required": False,
                "default": None
            },
            "password": {
                "type": "str",
                "description": "密码或密码文件路径",
                "required": False,
                "default": None
            },
            "hash": {
                "type": "str",
                "description": "NTLM哈希 (格式: LMHASH:NTHASH 或 :NTHASH)",
                "required": False,
                "default": None
            },
            "domain": {
                "type": "str",
                "description": "域名",
                "required": False,
                "default": None
            },
            "action": {
                "type": "str",
                "description": "动作: 'enum', 'users', 'groups', 'shares', 'sessions', 'disks', 'loggedon', 'pass-pol'",
                "required": False,
                "default": "enum"
            },
            "command": {
                "type": "str",
                "description": "要执行的命令 (用于 -x 参数)",
                "required": False,
                "default": None
            },
            "no_bruteforce": {
                "type": "bool",
                "description": "禁用暴力破解，仅测试给定凭据",
                "required": False,
                "default": True
            },
            "continue_on_success": {
                "type": "bool",
                "description": "成功后继续测试其他目标",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
       执行 crackmapexec 扫描
        """
        # 获取参数
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        protocol = params.get("protocol", "smb")
        username = params.get("username")
        password = params.get("password")
        hash_val = params.get("hash")
        domain = params.get("domain")
        action = params.get("action", "enum")
        command = params.get("command")
        no_bruteforce = params.get("no_bruteforce", True)
        continue_on_success = params.get("continue_on_success", False)

        # 构建命令
        cmd = [self.cmd_path, protocol, target]

        # 认证参数
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        if hash_val:
            cmd.extend(["-H", hash_val])
        if domain:
            cmd.extend(["-d", domain])

        # 动作参数
        if action == "enum":
            # 枚举模式
            if protocol == "smb":
                cmd.append("--shares")  # 列出共享
        elif action == "users":
            cmd.append("--users")
        elif action == "groups":
            cmd.append("--groups")
        elif action == "shares":
            cmd.append("--shares")
        elif action == "sessions":
            cmd.append("--sessions")
        elif action == "disks":
            cmd.append("--disks")
        elif action == "loggedon":
            cmd.append("--loggedon-users")
        elif action == "pass-pol":
            cmd.append("--pass-pol")

        # 命令执行
        if command:
            cmd.extend(["-x", command])

        # 控制参数
        if no_bruteforce:
            cmd.append("--no-bruteforce")
        if continue_on_success:
            cmd.append("--continue-on-success")

        # 输出格式
        cmd.extend(["--json"])  # JSON输出

        try:
            # 执行扫描 - 使用流式输出
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            if not stdout and "error" in raw_result:
                return {
                    "success": False,
                    "error": raw_result.get("error"),
                    "command": ' '.join(cmd)
                }

            # 解析结果
            results = self._parse_output(stdout, protocol)

            return {
                "success": True,
                "target": target,
                "protocol": protocol,
                "command": raw_result.get('command', ''),
                "results": results,
                "stdout": stdout,
                "stderr": stderr
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _parse_output(self, output: str, protocol: str) -> List[Dict]:
        """解析 crackmapexec 输出"""
        results = []

        # 尝试解析JSON输出
        try:
            for line in output.strip().split('\n'):
                if line.strip() and line.startswith('{'):
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

        # 如果JSON解析失败，尝试正则提取
        if not results:
            results = self._regex_parse(output, protocol)

        return results

    def _regex_parse(self, output: str, protocol: str) -> List[Dict]:
        """正则备用解析"""
        results = []

        # SMB状态匹配
        smb_pattern = re.compile(
            r'(\S+)\s+(\d+)\s+([^\s]+)\s+(.*?)\s*$',
            re.MULTILINE
        )

        # 成功认证匹配
        auth_success = re.compile(
            r'\[\+\]\s+(\S+)\s+.*?(\S+)\\(\S+)\s+(.*)'
        )

        for match in auth_success.finditer(output):
            results.append({
                "host": match.group(1),
                "domain": match.group(2),
                "username": match.group(3),
                "status": "success",
                "details": match.group(4)
            })

        return results