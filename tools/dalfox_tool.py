# tools/dalfox_tool.py
"""
Dalfox - XSS 扫描工具

功能:
- 单目标 XSS 扫描
- 参数 Fuzz
- 自动化 Payload 生成
- 支持多种输出格式

安装:
    go install github.com/hahwul/dalfox/v2@latest

使用:
    dalfox url <URL>           # 单目标扫描
    dalfox file <FILE>         # 批量扫描
    dalfox pipe < URLS         # 管道输入
"""
import os
import json
import re
import shutil
from typing import Dict, Any, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class DalfoxTool(CommandLineTool):
    """
    Dalfox XSS 扫描工具封装

    特点:
    - 快速 XSS 检测
    - 支持 GET/POST 参数
    - 自定义 Payload
    - JSON 输出支持
    """

    def __init__(self):
        super().__init__("dalfox")
        self.timeout = 180  # 3分钟超时

    def name(self) -> str:
        return "dalfox"

    def description(self) -> str:
        return "Dalfox XSS 扫描工具，快速检测 XSS 漏洞，支持参数 Fuzz 和自定义 Payload"

    def supported_vulns(self) -> List[str]:
        return [
            "XSS",
            "Cross-Site Scripting",
            "Reflected XSS",
            "Stored XSS",
            "DOM XSS",
            "Parameter Injection"
        ]

    def capability_statement(self) -> str:
        return "XSS 扫描工具。检测反射型、存储型、DOM 型 XSS。适合：参数 Fuzz、Payload 测试、漏洞验证。"

    def check_available(self) -> bool:
        """检查 dalfox 是否可用"""
        return shutil.which("dalfox") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL，如 'http://example.com/search?q=test'",
                "required": True
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
                "required": False,
                "default": None
            },
            "custom_payload": {
                "type": "str",
                "description": "自定义 XSS payload 文件路径",
                "required": False,
                "default": None
            },
            "cookies": {
                "type": "str",
                "description": "Cookie 值",
                "required": False,
                "default": None
            },
            "header": {
                "type": "str",
                "description": "自定义请求头，如 'Authorization: Bearer token'",
                "required": False,
                "default": None
            },
            "blind": {
                "type": "str",
                "description": "Blind XSS 回调地址",
                "required": False,
                "default": None
            },
            "timeout": {
                "type": "int",
                "description": "请求超时时间(秒)",
                "required": False,
                "default": 10
            },
            "delay": {
                "type": "int",
                "description": "请求间隔(毫秒)",
                "required": False,
                "default": 0
            },
            "only_discovery": {
                "type": "bool",
                "description": "仅发现模式，不发送实际攻击 Payload",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 XSS 扫描

        Args:
            target: 目标 URL (可被 params["url"] 覆盖)
            params: 扫描参数

        Returns:
            扫描结果字典
        """
        url = params.get("url") or target
        if not url:
            return {
                "success": False,
                "error": "必须提供目标 URL",
                "vulnerable": False,
                "summary": "缺少目标 URL"
            }

        # 检查工具可用性
        if not self.check_available():
            return {
                "success": False,
                "error": "dalfox 未安装。安装: go install github.com/hahwul/dalfox/v2@latest",
                "vulnerable": False,
                "summary": "工具不可用"
            }

        # 构建命令
        cmd = [
            "dalfox", "url", url,
            "--format", "json",  # JSON 输出
            "--silence",  # 静默模式，只输出结果
            "--no-color",  # 禁用颜色
            "--no-spinner"  # 禁用进度条
        ]

        # 请求方法
        method = params.get("method", "GET").upper()
        if method == "POST":
            cmd.append("--method")
            cmd.append("POST")
            if params.get("data"):
                cmd.extend(["--data", params["data"]])

        # Cookie
        if params.get("cookies"):
            cmd.extend(["--cookie", params["cookies"]])

        # 自定义请求头
        if params.get("header"):
            cmd.extend(["--header", params["header"]])

        # 自定义 Payload
        if params.get("custom_payload"):
            cmd.extend(["--custom-payload", params["custom_payload"]])

        # Blind XSS
        if params.get("blind"):
            cmd.extend(["--blind", params["blind"]])

        # 超时设置
        cmd.extend(["--timeout", str(params.get("timeout", 10))])

        # 请求间隔
        if params.get("delay"):
            cmd.extend(["--delay", str(params["delay"])])

        # 仅发现模式
        if params.get("only_discovery"):
            cmd.append("--only-discovery")

        try:
            # 执行命令
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 解析 JSON 输出
            xss_findings = []
            try:
                # Dalfox 可能输出多行 JSON
                for line in stdout.strip().split("\n"):
                    if line.strip() and line.startswith("{"):
                        try:
                            item = json.loads(line)
                            if item.get("type") == "vulnerability":
                                xss_findings.append({
                                    "url": item.get("data", {}).get("url", url),
                                    "param": item.get("data", {}).get("param", ""),
                                    "payload": item.get("data", {}).get("payload", ""),
                                    "evidence": item.get("data", {}).get("evidence", ""),
                                    "severity": item.get("data", {}).get("severity", "medium")
                            })
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass

            # 如果 JSON 解析失败，尝试正则提取
            if not xss_findings:
                # 查找 "[V] Detected XSS" 等标记
                xss_pattern = re.compile(
                    r"\[V\].*?(https?://[^\s]+).*?param[:\s]+(\w+).*?payload[:\s]+([^\n]+)",
                    re.IGNORECASE
                )
                for match in xss_pattern.finditer(stdout):
                    xss_findings.append({
                        "url": match.group(1),
                        "param": match.group(2),
                        "payload": match.group(3).strip(),
                        "severity": "medium"
                    })

            # 判断是否发现 XSS
            vulnerable = len(xss_findings) > 0

            # 使用 AI 分析结果
            if vulnerable and stdout:
                analysis = self._analyze_with_ai(url, xss_findings, stdout[:2000])
            else:
                analysis = {"summary": "未发现 XSS 漏洞", "next_steps": []}

            result = {
                "success": True,
                "vulnerable": vulnerable,
                "xss_findings": xss_findings,
                "url": url,
                "method": method,
                "summary": analysis.get("summary", f"{'发现' if vulnerable else '未发现'} XSS 漏洞"),
                "next_steps": analysis.get("next_steps", []),
                "total_findings": len(xss_findings)
            }

            # 保留原始输出
            result["stdout"] = stdout[:3000]
            result["stderr"] = stderr[:1000] if stderr else ""

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"扫描失败: {str(e)}"
            }

    def _analyze_with_ai(self, url: str, findings: List[Dict], raw_output: str) -> Dict:
        """使用 AI 分析 XSS 扫描结果"""
        prompt = f"""分析 Dalfox XSS 扫描结果，提取关键信息。

## 目标 URL
{url}

## 发现的 XSS
{json.dumps(findings, ensure_ascii=False, indent=2)}

## 原始输出片段
{raw_output}

## 输出要求 (JSON)
{{
  "summary": "扫描结果摘要",
  "risk_level": "high/medium/low",
  "next_steps": ["建议的下一步操作"]
}}
"""
        try:
            response = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )

            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]

            return json.loads(response.strip())

        except Exception:
            return {"summary": f"发现 {len(findings)} 个 XSS 漏洞", "next_steps": []}


def register():
    """注册工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(DalfoxTool())