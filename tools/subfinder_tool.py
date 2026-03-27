# tools/subfinder_tool.py
"""
Subfinder Tool - 子域名发现工具
快速发现目标域名的子域名
"""
import os
import json
import shutil
import subprocess
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class SubfinderTool(CommandLineTool):
    """
    Subfinder 子域名发现工具封装
    """

    def __init__(self):
        # 检测 subfinder 是否可用
        self.executable = shutil.which("subfinder")

        # 检查常见路径
        if not self.executable:
            common_paths = [
                "/usr/local/bin/subfinder",
                "/opt/linux/subfinder",
                "/root/go/bin/subfinder",
            ]
            for path in common_paths:
                if os.path.exists(path):
                    self.executable = path
                    break

        if self.executable:
            self.cmd_path = self.executable
        else:
            self.cmd_path = "subfinder"

        super().__init__(self.cmd_path)
        self.timeout = 180

    def name(self) -> str:
        return "subfinder"

    def description(self) -> str:
        return "子域名发现工具，快速枚举目标域名的子域名。"

    def supported_vulns(self) -> list:
        return ["Subdomain Enumeration", "Asset Discovery", "Information Disclosure", "Reconnaissance"]

    def capability_statement(self) -> str:
        return "子域名发现工具。输入主域名，自动发现子域名。适合：资产收集、渗透测试前期侦察。"

    def check_available(self) -> bool:
        if self.executable and os.path.exists(self.executable):
            return True
        return shutil.which("subfinder") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "domain": {
                "type": "str",
                "description": "目标域名，如 example.com",
                "required": True
            },
            "recursive": {
                "type": "bool",
                "description": "是否递归发现",
                "required": False,
                "default": False
            },
            "threads": {
                "type": "int",
                "description": "并发线程数",
                "required": False,
                "default": 10
            },
            "output_file": {
                "type": "str",
                "description": "输出文件路径",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        domain = params.get("domain") or target

        if not domain:
            return {"success": False, "error": "必须提供域名"}

        if not self.check_available():
            return {
                "success": False,
                "error": "subfinder 未安装。下载地址: https://github.com/projectdiscovery/subfinder"
            }

        cmd = [self.cmd_path, "-d", domain, "-silent", "-json"]

        # 递归
        if params.get("recursive"):
            cmd.append("-recursive")

        # 线程数
        if params.get("threads"):
            cmd.extend(["-t", str(params["threads"])])

        try:
            result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = result.get("stdout", "")

            # 解析结果
            subdomains = []
            for line in stdout.strip().split("\n"):
                if line and line.startswith("{"):
                    try:
                        data = json.loads(line)
                        host = data.get("host", "")
                        if host and host not in subdomains:
                            subdomains.append(host)
                    except json.JSONDecodeError:
                        # 尝试作为普通域名处理
                        if line and line not in subdomains:
                            subdomains.append(line.strip())

            return {
                "success": result.get("returncode", 0) == 0,
                "domain": domain,
                "subdomains": subdomains,
                "total": len(subdomains),
                "summary": f"发现 {len(subdomains)} 个子域名"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


def register():
    """注册Subfinder工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(SubfinderTool())