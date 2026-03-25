# tools/xray_scanner.py
"""
Xray漏洞扫描器集成

Xray是长亭科技开源的漏洞扫描器，支持：
- 主动扫描模式
- 被动代理模式
- 自定义POC
- JSON/HTML报告输出
"""

import os
import json
import shutil
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from tool_framework import CommandLineTool


class XrayScanner(CommandLineTool):
    """
    Xray漏洞扫描器封装

    功能：
    - Web应用漏洞扫描
    - 主动爬虫模式
    - 单URL扫描
    - 自定义POC加载
    """

    def __init__(self):
        self.executable = self._find_xray()
        super().__init__(self.executable or "xray")
        self.timeout = 600  # 10分钟超时

    def _find_xray(self) -> Optional[str]:
        """查找xray可执行文件"""
        # 检查常见路径
        common_paths = [
            "/usr/local/bin/xray",
            "/usr/bin/xray",
            "/app/xray",
            shutil.which("xray") or ""
        ]
        for path in common_paths:
            if path and os.path.exists(path):
                return path
        return None

    def name(self) -> str:
        return "xray"

    def description(self) -> str:
        return "Xray安全评估工具，支持主动扫描、POC验证、常见Web漏洞检测。"

    def supported_vulns(self) -> list:
        return [
            "SQL Injection", "XSS", "SSRF", "XXE",
            "File Upload", "Path Traversal", "RCE",
            "Spring Boot", "Shiro", "FastJSON", "WebLogic",
            "ThinkPHP", "Struts2"
        ]

    def capability_statement(self) -> str:
        return "综合漏洞扫描器。主动模式扫描Web应用，检测SQL注入/XSS/SSRF/XXE/RCE等。适合：已发现Web应用、需要深度漏洞检测、与其他漏扫工具配合使用。"

    def check_available(self) -> bool:
        """检查xray是否可用"""
        if not self.executable:
            return False
        try:
            result = subprocess.run(
                [self.executable, "version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL",
                "required": True
            },
            "mode": {
                "type": "str",
                "description": "扫描模式: webscan(主动扫描), passive(被动代理)",
                "required": False,
                "default": "webscan"
            },
            "poc": {
                "type": "str",
                "description": "自定义POC文件或目录",
                "required": False
            },
            "html_output": {
                "type": "bool",
                "description": "是否生成HTML报告",
                "required": False,
                "default": False
            },
            "json_output": {
                "type": "bool",
                "description": "是否输出JSON格式",
                "required": False,
                "default": True
            },
            "plugins": {
                "type": "list",
                "description": "启用的插件列表，如['sqldet', 'xss']",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """执行Xray扫描"""
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标URL", "success": False}

        if not self.check_available():
            return {
                "error": "Xray未安装。下载地址: https://github.com/chaitin/xray/releases",
                "success": False
            }

        mode = params.get("mode", "webscan")

        # 创建临时输出文件
        output_file = tempfile.mktemp(suffix=".json", prefix="xray_")

        try:
            cmd = [self.executable, mode]

            if mode == "webscan":
                # 主动扫描模式
                cmd.extend(["--url", target])

                # 输出格式
                if params.get("json_output", True):
                    cmd.extend(["--json-output", output_file])
                elif params.get("html_output"):
                    html_file = output_file.replace(".json", ".html")
                    cmd.extend(["--html-output", html_file])

                # 自定义POC
                poc = params.get("poc")
                if poc:
                    cmd.extend(["--poc", poc])

            # 执行扫描 - 使用基类的流式输出方法
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 解析结果
            vulnerabilities = []
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                vuln = json.loads(line)
                                vulnerabilities.append(self._parse_result(vuln))
                            except json.JSONDecodeError:
                                continue

            return {
                "success": True,
                "vulnerable": len(vulnerabilities) > 0,
                "target": target,
                "command": raw_result.get('command', ''),
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "stdout": stdout[:5000] if stdout else "",
                "stderr": stderr[:2000] if stderr else ""
            }

        except Exception as e:
            return {
                "error": str(e),
                "success": False,
                "target": target
            }
        finally:
            # 清理临时文件
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass

    def _parse_result(self, raw_result: Dict) -> Dict:
        """解析Xray输出结果"""
        plugin = raw_result.get("plugin", "")
        detail = raw_result.get("detail", {})

        return {
            "plugin": plugin,
            "url": detail.get("url", ""),
            "vuln_class": detail.get("vuln_class", ""),
            "description": detail.get("descr", ""),
            "request": detail.get("request", "")[:1000],
            "response": detail.get("response", "")[:1000],
            "severity": self._get_severity(plugin),
            "timestamp": raw_result.get("time", "")
        }

    def _get_severity(self, plugin: str) -> str:
        """根据插件类型判断严重程度"""
        critical_plugins = ["struts2", "thinkphp", "fastjson", "weblogic", "shiro"]
        high_plugins = ["sqldet", "xxe", "upload", "brute_force"]
        medium_plugins = ["xss", "ssrf", "dirscan", "phantasm"]

        plugin_lower = plugin.lower()
        if any(p in plugin_lower for p in critical_plugins):
            return "critical"
        elif any(p in plugin_lower for p in high_plugins):
            return "high"
        elif any(p in plugin_lower for p in medium_plugins):
            return "medium"
        return "low"

    # ==================== 快捷方法 ====================

    def scan_url(self, target: str) -> Dict:
        """快速URL扫描"""
        return self.execute(target, {"mode": "webscan"})

    def scan_with_poc(self, target: str, poc_path: str) -> Dict:
        """使用自定义POC扫描"""
        return self.execute(target, {"mode": "webscan", "poc": poc_path})


def register():
    """注册Xray扫描器"""
    from tool_framework import ToolRegistry
    scanner = XrayScanner()
    ToolRegistry.register(scanner)