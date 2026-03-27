# tools/xray_tool.py
"""
Xray Tool - 长亭漏洞扫描器

功能:
- 被动扫描模式 (代理抓取)
- 主动扫描模式 (爬虫+扫描)
- 支持多种漏洞检测
- 生成详细报告

特点:
- 国产优秀扫描器
- 误报率低
- 支持自定义POC

CTF优化:
- 主动扫描模式，一键扫描
- JSON输出便于解析
"""
import os
import json
import shutil
import subprocess
import tempfile
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class XrayTool(CommandLineTool):
    """
    Xray 漏洞扫描工具封装

    支持两种模式:
    - 主动扫描: xray webscan --url target
    - 被动扫描: xray webscan --listen 7777 (需要配合浏览器代理)
    """

    # 前置条件
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "recon"  # 侦察工具

    def __init__(self):
        # 检测 xray 是否可用
        self.executable = None
        possible_paths = [
            "/usr/local/bin/xray",
            "/usr/bin/xray",
            "/opt/linux/xray",
            "xray"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                self.executable = path
                break

        if not self.executable:
            self.executable = shutil.which("xray")

        super().__init__(self.executable or "xray")
        self.timeout = 600  # 10分钟超时

    def name(self) -> str:
        return "xray"

    def description(self) -> str:
        return "长亭漏洞扫描器，主动/被动模式检测Web漏洞，支持自定义POC。"

    def supported_vulns(self) -> list:
        return [
            "SQL Injection",
            "XSS",
            "SSRF",
            "XXE",
            "RCE",
            "File Upload",
            "Path Traversal",
            "CVE Detection",
            "Vulnerability Scan"
        ]

    def capability_statement(self) -> str:
        return "Web漏洞扫描器。输入URL，自动爬取并扫描漏洞。适合：Web应用渗透测试、漏洞验证。侦察节点使用。"

    def check_available(self) -> bool:
        """检查 xray 是否可用"""
        if self.executable and os.path.exists(self.executable):
            return True
        try:
            result = subprocess.run(
                ["xray", "version"],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0 or b"xray" in result.stdout.lower():
                self.executable = "xray"
                return True
            return False
        except Exception:
            return False

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "target": {
                "type": "str",
                "description": "目标URL (如 http://example.com)",
                "required": True
            },
            "plugins": {
                "type": "list",
                "description": "启用的插件列表 (如 ['sqldet', 'xss', 'ssrf'])",
                "required": False
            },
            "poc": {
                "type": "str",
                "description": "自定义POC文件路径",
                "required": False
            },
            "output_format": {
                "type": "str",
                "description": "输出格式: json, html",
                "required": False,
                "default": "json"
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 xray 扫描 - 主动扫描模式
        """
        target = params.get("target") or target
        if not target:
            return {"error": "必须提供目标URL", "success": False}

        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target

        # 创建临时输出文件
        output_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        output_path = output_file.name
        output_file.close()

        # 构建命令
        cmd = [self.executable or "xray", "webscan", "--url", target]

        # 输出文件
        cmd.extend(["--json-output", output_path])

        # 基础扫描参数
        cmd.append("--basic-crawler")

        print(f"[Xray] Executing: {' '.join(cmd)}")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 读取结果文件
            vulnerabilities = []
            if os.path.exists(output_path):
                try:
                    with open(output_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    vuln = {
                                        "plugin": data.get("plugin", ""),
                                        "url": data.get("target", {}).get("url", ""),
                                        "title": data.get("value", {}).get("title", ""),
                                        "severity": self._get_severity(data.get("value", {}).get("level", "")),
                                        "detail": data.get("value", {}).get("detail", "")
                                    }
                                    vulnerabilities.append(vuln)
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    print(f"[Xray] Error reading output file: {e}")
                finally:
                    try:
                        os.unlink(output_path)
                    except:
                        pass

            return {
                "success": raw_result.get("success", False),
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total": len(vulnerabilities),
                "summary": f"发现 {len(vulnerabilities)} 个漏洞",
                "stdout": stdout + "\n" + stderr
            }

        except Exception as e:
            # 清理临时文件
            try:
                if os.path.exists(output_path):
                    os.unlink(output_path)
            except:
                pass
            return {
                "success": False,
                "error": str(e),
                "target": target
            }

    def _get_severity(self, level: str) -> str:
        """转换严重级别"""
        level_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }
        return level_map.get(level.lower(), "medium")


def register():
    """注册 Xray 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(XrayTool())