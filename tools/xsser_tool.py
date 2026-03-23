# tools/xsser_tool.py
# XSSer - XSS 自动化攻击工具
import os
import json
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class XSSerTool(CommandLineTool):
    """
    XSSer 封装 - XSS 自动化攻击框架
    检测和利用 XSS 漏洞
    """

    def __init__(self):
        super().__init__("xsser")
        self.timeout = 120

    def name(self) -> str:
        return "xsser"

    def description(self) -> str:
        return "XSS 自动化攻击框架，检测和利用跨站脚本漏洞"

    def supported_vulns(self) -> list:
        return ["XSS", "Cross-Site Scripting", "Reflected XSS", "Stored XSS", "DOM XSS"]

    def check_available(self) -> bool:
        import shutil
        return shutil.which("xsser") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL，如 'http://example.com/search?q='",
                "required": True
            },
            "payload": {
                "type": "str",
                "description": "自定义 XSS payload",
                "required": False,
                "default": "<script>alert('XSS')</script>"
            },
            "method": {
                "type": "str",
                "description": "请求方法: GET, POST (默认 GET)",
                "required": False,
                "default": "GET"
            },
            "data": {
                "type": "str",
                "description": "POST 数据，如 'param1=value1&param2=value2'",
                "required": False
            },
            "cookies": {
                "type": "str",
                "description": "Cookie 值",
                "required": False
            },
            "reverse_check": {
                "type": "bool",
                "description": "是否使用反向连接检查",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        url = params.get("url")
        if not url:
            raise ValueError("必须提供 url 参数")

        cmd = ["xsser", "-u", url]

        # 添加选项
        payload = params.get("payload")
        if payload:
            cmd.extend(["--payload", payload])

        method = params.get("method", "GET")
        if method.upper() == "POST":
            cmd.append("--POST")

        data = params.get("data")
        if data:
            cmd.extend(["-d", data])

        cookies = params.get("cookies")
        if cookies:
            cmd.extend(["--cookie", cookies])

        if params.get("reverse_check"):
            cmd.append("--reverse-check")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 分析结果
            xss_found = "XSS" in stdout and ("found" in stdout.lower() or "vulnerable" in stdout.lower())

            result = {
                "success": True,
                "vulnerable": xss_found,
                "url": url,
                "method": method,
                "payload": payload,
                "output": stdout[:3000] if stdout else "",
                "summary": f"XSS 检测{'发现漏洞' if xss_found else '未发现明显漏洞'}"
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