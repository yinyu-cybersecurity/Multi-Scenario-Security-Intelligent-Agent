# tools/httpx_tool.py
"""
HTTPX Tool - HTTP探测工具
快速探测HTTP服务，支持多种输出格式
"""
import os
import json
import shutil
import subprocess
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class HTTPXTool(CommandLineTool):
    """
    HTTPX HTTP探测工具封装
    """

    def __init__(self):
        # 检测 httpx 是否可用
        self.executable = shutil.which("httpx")

        # 检查常见路径
        if not self.executable:
            common_paths = [
                "/usr/local/bin/httpx",
                "/opt/linux/httpx",
                "/root/go/bin/httpx",
            ]
            for path in common_paths:
                if os.path.exists(path):
                    self.executable = path
                    break

        if self.executable:
            self.cmd_path = self.executable
        else:
            self.cmd_path = "httpx"

        super().__init__(self.cmd_path)
        self.timeout = 120

    def name(self) -> str:
        return "httpx"

    def description(self) -> str:
        return "HTTP探测工具，快速探测HTTP服务并收集信息。"

    def supported_vulns(self) -> list:
        return ["HTTP Probe", "Service Detection", "Technology Fingerprint", "Information Disclosure"]

    def capability_statement(self) -> str:
        return "HTTP探测工具。输入域名/IP列表，自动探测HTTP服务。适合：资产发现、存活探测、技术栈识别。"

    def check_available(self) -> bool:
        if self.executable and os.path.exists(self.executable):
            return True
        return shutil.which("httpx") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL或文件路径",
                "required": True
            },
            "ports": {
                "type": "str",
                "description": "要探测的端口，如 '80,443,8080'",
                "required": False
            },
            "title": {
                "type": "bool",
                "description": "是否获取页面标题",
                "required": False,
                "default": True
            },
            "tech_detect": {
                "type": "bool",
                "description": "是否检测技术栈",
                "required": False,
                "default": True
            },
            "json_output": {
                "type": "bool",
                "description": "是否输出JSON格式",
                "required": False,
                "default": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        if not self.check_available():
            return {
                "success": False,
                "error": "httpx 未安装。下载地址: https://github.com/projectdiscovery/httpx"
            }

        cmd = [self.cmd_path]

        # 添加目标
        cmd.append("-u")
        cmd.append(target)

        # 输出格式
        if params.get("json_output", True):
            cmd.append("-json")

        # 页面标题
        if params.get("title", True):
            cmd.append("-title")

        # 技术检测
        if params.get("tech_detect", True):
            cmd.append("-tech-detect")

        # 端口
        if params.get("ports"):
            cmd.extend(["-ports", params["ports"]])

        try:
            result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = result.get("stdout", "")

            # 解析结果
            hosts = []
            for line in stdout.strip().split("\n"):
                if line and line.startswith("{"):
                    try:
                        data = json.loads(line)
                        hosts.append({
                            "url": data.get("url", ""),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                            "status_code": data.get("status_code", 0),
                            "content_length": data.get("content_length", 0)
                        })
                    except json.JSONDecodeError:
                        continue

            return {
                "success": result.get("returncode", 0) == 0,
                "hosts": hosts,
                "total": len(hosts),
                "summary": f"发现 {len(hosts)} 个HTTP服务"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


def register():
    """注册HTTPX工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(HTTPXTool())