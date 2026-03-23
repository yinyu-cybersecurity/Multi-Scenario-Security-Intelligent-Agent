# tools/jsfinder_tool.py
# JS 文件信息提取工具
import sys
import os
import json
import re
from typing import Dict, Any
from tool_framework import CommandLineTool


class JSFinderTool(CommandLineTool):
    """
    JSFinder 封装 - 从 JS 文件中提取敏感信息
    可发现 API 接口、URL、敏感路径等
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        docker_path = "/app/thirdparty/jsfinder/JSFinder.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "jsfinder", "JSFinder.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 120

    def name(self) -> str:
        return "jsfinder"

    def description(self) -> str:
        return "JS 文件信息提取工具，从 JS 中发现 URL、API 接口、敏感路径"

    def supported_vulns(self) -> list:
        return ["Information Disclosure", "API Discovery", "Hidden Endpoints", "Sensitive Paths"]

    def check_available(self) -> bool:
        return os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL",
                "required": True
            },
            "deep": {
                "type": "bool",
                "description": "是否深度扫描（扫描更多 JS 文件）",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL")

        cmd = [self.cmd_path, self.script_path, "-u", url]

        if params.get("deep"):
            cmd.append("-d")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 提取发现的 URL 和 API
            urls = re.findall(r'https?://[^\s\'"<>]+', stdout)
            apis = re.findall(r'/api/[\w/\-]+', stdout)
            sensitive_paths = re.findall(r'/[\w/\-]+\.(php|asp|jsp|json|xml)', stdout)

            # 去重
            urls = list(set(urls))[:30]
            apis = list(set(apis))[:20]
            sensitive_paths = list(set(sensitive_paths))[:20]

            result = {
                "success": raw_result.get("success", False),
                "vulnerable": len(urls) > 0 or len(apis) > 0,
                "discovered_urls": urls,
                "discovered_apis": apis,
                "sensitive_paths": sensitive_paths,
                "summary": f"发现 {len(urls)} 个 URL, {len(apis)} 个 API 接口"
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