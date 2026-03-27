# tools/nuclei_tool.py
"""
Nuclei Tool - 快速漏洞扫描器

功能:
- 基于模板的漏洞扫描
- CVE漏洞检测
- 技术指纹识别
- 支持多种协议 (HTTP, TCP, DNS, SSL等)

特点:
- 模板丰富，社区持续更新
- 扫描速度快
- 支持自定义模板

CTF优化:
- 自动更新模板
- 简化参数，一次扫描完成
"""
import os
import shutil
import subprocess
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class NucleiTool(CommandLineTool):
    """
    Nuclei 漏洞扫描工具封装

    简化使用：nuclei -u target，使用默认模板扫描
    """

    # 前置条件
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "recon"  # 侦察工具

    def __init__(self):
        # 检测 nuclei 是否可用
        self.executable = None
        possible_paths = [
            "/usr/local/bin/nuclei",
            "/usr/bin/nuclei",
            "/opt/linux/nuclei",
            "nuclei"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                self.executable = path
                break

        if not self.executable:
            self.executable = shutil.which("nuclei")

        super().__init__(self.executable or "nuclei")
        self.timeout = 300  # 5分钟超时

    def name(self) -> str:
        return "nuclei"

    def description(self) -> str:
        return "快速漏洞扫描器，基于模板检测CVE、技术指纹、配置错误等漏洞。"

    def supported_vulns(self) -> list:
        return [
            "CVE Detection",
            "Technology Fingerprint",
            "Vulnerability Scan",
            "Misconfiguration",
            "Information Disclosure",
            "Exposed Service"
        ]

    def capability_statement(self) -> str:
        return "漏洞扫描器。输入URL/IP，自动使用模板扫描已知漏洞。适合：资产评估、CVE检测、技术栈识别。侦察节点使用。"

    def check_available(self) -> bool:
        """检查 nuclei 是否可用"""
        if self.executable and os.path.exists(self.executable):
            return True
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                self.executable = "nuclei"
                return True
            return False
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL或IP (如 http://example.com, 192.168.1.1)",
                "required": True
            },
            "severity": {
                "type": "str",
                "description": "最低严重级别: critical, high, medium, low, info",
                "required": False,
                "default": "medium"
            },
            "templates": {
                "type": "str",
                "description": "指定模板目录或模板标签 (如 cve, exposures, tech)",
                "required": False
            },
            "no_update": {
                "type": "bool",
                "description": "跳过模板更新（加速扫描）",
                "required": False,
                "default": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 nuclei 扫描
        """
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标", "success": False}

        # 构建命令
        cmd = [self.executable or "nuclei"]

        # 目标
        if target.startswith("http://") or target.startswith("https://"):
            cmd.extend(["-u", target])
        else:
            cmd.extend(["-u", target])

        # 输出格式
        cmd.extend(["-json", "-silent"])

        # 严重级别过滤
        severity = params.get("severity", "medium")
        cmd.extend(["-severity", severity])

        # 模板更新
        if params.get("no_update", True):
            cmd.append("-nut")

        # 指定模板
        templates = params.get("templates")
        if templates:
            cmd.extend(["-t", templates])

        print(f"[Nuclei] Executing: {' '.join(cmd)}")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 解析结果
            vulnerabilities = []
            for line in stdout.strip().split("\n"):
                if line and line.startswith("{"):
                    try:
                        import json
                        data = json.loads(line)
                        vuln = {
                            "template": data.get("template-id", ""),
                            "name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", "unknown"),
                            "matched_at": data.get("matched-at", data.get("host", "")),
                            "type": data.get("type", ""),
                            "curl_command": data.get("curl-command", "")
                        }
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue

            return {
                "success": raw_result.get("success", False),
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total": len(vulnerabilities),
                "summary": f"发现 {len(vulnerabilities)} 个漏洞/信息",
                "stdout": stdout
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "target": target
            }


def register():
    """注册 Nuclei 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(NucleiTool())