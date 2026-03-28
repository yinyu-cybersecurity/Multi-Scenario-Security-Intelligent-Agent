# tools/ffuf_tool.py
# FFUF - Web 模糊测试工具
import os
import json
import re
import shutil
from typing import Dict, Any
from tool_framework import CommandLineTool


class FFUFTool(CommandLineTool):
    """
    FFUF 封装 - Go 语言编写的高速 Web 模糊测试工具
    支持目录爆破、参数 fuzz、子域名发现等
    """

    def __init__(self):
        super().__init__("ffuf")
        self.timeout = 180

    def name(self) -> str:
        return "ffuf"

    def description(self) -> str:
        return "高速 Web 模糊测试工具，用于目录爆破、参数 Fuzz、子域名发现"

    def supported_vulns(self) -> list:
        return ["Hidden Paths", "API Discovery", "Parameter Discovery", "Subdomain Discovery", "Information Disclosure"]

    def check_available(self) -> bool:
        # 检查 ffuf 是否在 PATH 中或常见路径
        import shutil

        # 检查系统 PATH
        if shutil.which("ffuf"):
            return True

        # 检查常见路径（多种可能的文件名）
        common_paths = [
            "/usr/local/bin/ffuf",
            "/usr/local/bin/ffuf_linux_amd64",  # 解压后原始文件名
            "/usr/local/bin/ffuf_2.1.0_linux_amd64",
            "/usr/bin/ffuf",
            "/opt/linux/ffuf",
        ]
        for path in common_paths:
            if os.path.exists(path):
                return True

        return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL，使用 FUZZ 关键字标记爆破位置，如 http://example.com/FUZZ",
                "required": True
            },
            "wordlist": {
                "type": "str",
                "description": "字典文件路径",
                "required": False,
                "default": "/app/data/security_resources/SecLists-master/Discovery/Web-Content/common.txt"
            },
            "mode": {
                "type": "str",
                "description": "模式: dir(目录), param(参数), vhost(子域名)",
                "required": False,
                "default": "dir"
            },
            "extensions": {
                "type": "str",
                "description": "文件扩展名，如 php,html,js",
                "required": False,
                "default": None
            },
            "threads": {
                "type": "int",
                "description": "并发线程数",
                "required": False,
                "default": 40
            },
            "match_status": {
                "type": "str",
                "description": "匹配的状态码，如 200,301,302",
                "required": False,
                "default": "200,301,302,403"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL")

        # 如果 URL 中没有 FUZZ 关键字，自动添加
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        cmd = [
            "ffuf",
            "-u", url,
            "-w", params.get("wordlist", "/app/data/security_resources/SecLists-master/Discovery/Web-Content/common.txt"),
            "-t", str(params.get("threads", 40)),
            "-mc", params.get("match_status", "200,301,302,403"),
            "-fs", "0",  # 过滤大小为 0 的响应
            "-v",  # 详细输出
            "-json"  # JSON 输出
        ]

        # 扩展名
        if params.get("extensions"):
            cmd.extend(["-e", params["extensions"]])

        # 模式特定配置
        mode = params.get("mode", "dir")
        if mode == "param":
            # 参数 fuzz 模式
            cmd.extend(["-method", "GET"])

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 解析 JSON 输出
            findings = []
            try:
                for line in stdout.strip().split("\n"):
                    if line.strip() and line.startswith("{"):
                        try:
                            item = json.loads(line)
                            if item.get("status"):
                                findings.append({
                                    "url": item.get("url", ""),
                                    "status": item.get("status"),
                                    "size": item.get("length", 0),
                                    "words": item.get("words", 0)
                                })
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass

            # 如果 JSON 解析失败，尝试正则提取
            if not findings:
                for match in re.finditer(r"(https?://[^\s]+)\s+(\d+)\s+(\d+)", stdout):
                    findings.append({
                        "url": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3))
                    })

            result = {
                "success": raw_result.get("success", False) or len(findings) > 0,
                "vulnerable": len(findings) > 0,
                "findings": findings[:50],
                "summary": f"发现 {len(findings)} 个有效路径"
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