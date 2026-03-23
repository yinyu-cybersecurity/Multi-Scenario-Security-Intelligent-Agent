# tools/fenjing_tool.py
import json
import shutil
from typing import Dict, Any, List
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


class FenjingTool(CommandLineTool):
    """
    Fenjing（焚靖）封装 — 专为 CTF 设计的 Jinja2 SSTI 全自动绕 WAF 工具。

    支持绕过：{{、_、引号、%、~、*、-、+、数字、[ 以及大多数敏感关键字。
    提供 CLI 和 Python 库两种调用模式。
    """

    def __init__(self):
        # fenjing 通过 pipx 安装在 PATH 中
        executable = shutil.which("fenjing")
        if not executable:
            # 尝试 python -m fenjing（Windows 本地调试场景）
            executable = "fenjing"
        super().__init__(executable)

    def name(self) -> str:
        return "fenjing"

    def description(self) -> str:
        return (
            "Jinja2 SSTI 全自动绕 WAF 工具（CTF 专用）。"
            "支持表单攻击、JSON API 攻击、路径攻击、自动扫描、源码关键字提取。"
            "可绕过 {{、_、引号、%、~、*、-、+、数字、[ 等关键字过滤。"
        )

    def supported_vulns(self) -> List[str]:
        return ["SSTI", "Jinja2 SSTI", "Template Injection", "SSTI WAF Bypass"]

    def check_available(self) -> bool:
        return shutil.which("fenjing") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "subcommand": {
                "type": "string",
                "description": (
                    "子命令类型："
                    "scan（扫描整个网站，自动发现参数并攻击）；"
                    "crack（针对特定表单攻击，需配合 url/inputs/method）；"
                    "crack-json（攻击 JSON API，需配合 url/json-data/key）；"
                    "crack-path（攻击特定路径，需配合 url）；"
                    "crack-keywords（从源码提取黑名单生成 payload，需配合 keywords-file/command）"
                ),
                "required": True,
                "options": ["scan", "crack", "crack-json", "crack-path", "crack-keywords"]
            },
            "url": {
                "type": "string",
                "description": "目标 URL（所有子命令都需要）",
                "required": True
            },
            "method": {
                "type": "string",
                "description": "表单提交方式：GET 或 POST（crack 子命令用）",
                "required": False,
                "default": "GET"
            },
            "inputs": {
                "type": "string",
                "description": "参数字段名，逗号分隔（crack 子命令用，如 'name,age'）",
                "required": False
            },
            "json_data": {
                "type": "string",
                "description": "JSON 请求体，格式为 JSON 字符串（crack-json 子命令用）",
                "required": False
            },
            "key": {
                "type": "string",
                "description": "JSON API 中 SSTI 注入点对应的键名（crack-json 子命令用）",
                "required": False
            },
            "keywords_file": {
                "type": "string",
                "description": "包含 WAF 黑名单关键字的源码文件路径（crack-keywords 子命令用）",
                "required": False
            },
            "command": {
                "type": "string",
                "description": "成功利用后要执行的 shell 指令（如 'cat /flag'）",
                "required": False,
                "default": "cat /flag"
            },
            "detect_mode": {
                "type": "string",
                "description": "检测模式：fast（快速，默认）或 accurate（精确但慢）",
                "required": False,
                "default": "fast"
            },
            "eval_args_payload": {
                "type": "bool",
                "description": "将 payload 放在 GET 参数 x 中提交，可缩短 payload 长度",
                "required": False,
                "default": False
            },
            "tamper_cmd": {
                "type": "string",
                "description": "发出前对 payload 编码：base64（base64 编码）、rev（反转）、base64 | rev（编码+反转）",
                "required": False
            }
        }

    def _build_command(self, subcommand: str, params: Dict) -> List[str]:
        """根据子命令构建 fenjing 命令行参数"""
        url = params.get("url", "")
        cmd = [self.cmd_path, subcommand, "--url", url]

        if subcommand == "crack":
            method = params.get("method", "GET")
            inputs = params.get("inputs", "")
            cmd.extend(["--method", method])
            if inputs:
                cmd.extend(["--inputs", inputs])

        elif subcommand == "crack-json":
            json_data = params.get("json_data", "")
            key = params.get("key", "")
            if json_data:
                cmd.extend(["--json-data", json_data])
            if key:
                cmd.extend(["--key", key])

        elif subcommand == "crack-keywords":
            kw_file = params.get("keywords_file", "")
            cmd_exec = params.get("command", "cat /flag")
            if kw_file:
                cmd.extend(["--keywords-file", kw_file])
            cmd.extend(["--command", cmd_exec])

        detect_mode = params.get("detect_mode", "fast")
        cmd.extend(["--detect-mode", detect_mode])

        if params.get("eval_args_payload"):
            cmd.append("--eval-args-payload")

        tamper = params.get("tamper_cmd")
        if tamper:
            cmd.extend(["--tamper-cmd", tamper])

        return cmd

    def execute(self, target: str, params: Dict) -> Dict:
        subcommand = params.get("subcommand", "scan")
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL（url 参数）")

        params = dict(params)  # 不修改原始 params
        params["url"] = url

        cmd = self._build_command(subcommand, params)
        raw_result = self._run_command(cmd)
        stdout = raw_result.get("stdout", "")
        stderr = raw_result.get("stderr", "")
        full_output = stdout + ("\n" + stderr if stderr else "")

        # 提取关键信息构建结构化结果
        summary = self._extract_summary(subcommand, full_output)
        findings = self._extract_findings(full_output)

        # AI 辅助分析输出
        analysis = self._analyze_output(full_output, subcommand, url)

        result = {
            "subcommand": subcommand,
            "summary": summary,
            "findings": findings,
            "is_exploit": analysis.get("is_exploit", False),
            "exploit_confidence": analysis.get("confidence", 0.0),
            "tactical_guidance": analysis.get("guidance", ""),
            "stdout": stdout,
            "stderr": stderr,
            "success": raw_result.get("success", False),
            "command": " ".join(cmd)
        }

        return result

    def _extract_summary(self, subcommand: str, output: str) -> str:
        """从原始输出中提取摘要"""
        if "Traceback" in output:
            return "执行出错（见 stderr）"
        if not output.strip():
            return "无输出"
        # 截取首尾各 500 字符
        if len(output) > 1000:
            return output[:500] + "\n...[省略]...\n" + output[-500:]
        return output

    def _extract_findings(self, output: str) -> List[str]:
        """提取关键发现"""
        findings = []
        if "payload:" in output.lower() or "exploit" in output.lower():
            findings.append("检测到潜在 SSTI Payload 输出")
        if "command executed" in output.lower() or "flag" in output.lower():
            findings.append("命令执行成功或发现 Flag 关键字")
        if "Traceback" in output:
            findings.append(f"执行错误：{output.split('Traceback')[-1][:200]}")
        return findings

    def _analyze_output(self, output: str, subcommand: str, url: str) -> Dict[str, Any]:
        """使用 LLM 分析 fenjing 输出，给出战术建议"""
        prompt = f"""
你是 Web 安全专家。分析 Fenjing SSTI 工具的执行输出。

### 执行子命令: {subcommand}
### 目标 URL: {url}

### 原始输出（末尾 4000 字符）:
{output[-4000:] if len(output) > 4000 else output}

### 输出要求 (JSON):
{{
    "is_exploit": boolean,      // 是否成功利用了 SSTI 漏洞
    "confidence": float,         // 置信度 0.0-1.0
    "guidance": "string",       // 战术建议：下一步应如何利用或读取 Flag
    "waf_bypass_technique": "string"  // 如果成功，使用的 WAF 绕过技术名称
}}
"""
        try:
            analysis_text = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                json_mode=True
            )
            if "```json" in analysis_text:
                analysis_text = analysis_text.split("```json")[1].split("```")[0]
            elif "```" in analysis_text:
                analysis_text = analysis_text.split("```")[1].split("```")[0]
            return json.loads(analysis_text)
        except Exception:
            return {"is_exploit": False, "confidence": 0.0, "guidance": ""}
