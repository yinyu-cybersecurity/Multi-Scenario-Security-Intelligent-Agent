# tools/sqlmap_tool.py
import re
import sys
import json
import os
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config


# [安全修复] URL 验证函数
def validate_url(url: str) -> Tuple[bool, str]:
    """
    验证 URL 参数，防止命令注入

    Args:
        url: 用户输入的 URL

    Returns:
        (is_valid, error_message): 验证结果和错误信息
    """
    if not url or not isinstance(url, str):
        return False, "URL 不能为空"

    url = url.strip()

    # 长度限制
    if len(url) > 2048:
        return False, "URL 长度超过限制"

    # 检查危险字符（命令注入防护）
    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '\n', '\r']
    for char in dangerous_chars:
        if char in url:
            return False, f"URL 包含非法字符: {char}"

    # 验证 URL 格式
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False, f"不支持的协议: {parsed.scheme}"
        if not parsed.netloc:
            return False, "URL 缺少主机名"
    except Exception as e:
        return False, f"无效的 URL 格式: {e}"

    return True, ""


class SqlmapTool(CommandLineTool):
    """
    sqlmap 封装 - 自动化检测和利用 SQL 注入漏洞
    """

    def __init__(self):
        # 1. 检测环境，智能选择执行方式
        import shutil
        import os
        
        # 检查是否在 Docker 容器内
        self.is_in_docker = os.path.exists("/.dockerenv")
        
        # 优先寻找系统路径中的 sqlmap 命令 (pipx 安装)
        self.executable = shutil.which("sqlmap")

        # pipx 安装的 sqlmap 在 /root/.local/bin/sqlmap
        if not self.executable:
            pipx_path = "/root/.local/bin/sqlmap"
            if os.path.exists(pipx_path):
                self.executable = pipx_path
        
        # 确定最终执行命令
        if self.executable:
            self.cmd_path = self.executable
            self.use_script = False
        else:
            self.cmd_path = "python3" if self.is_in_docker else sys.executable
            self.use_script = True

        super().__init__(self.cmd_path)

    def name(self) -> str:
        return "sqlmap"

    def description(self) -> str:
        return "自动化 SQL 注入检测与利用工具，支持多种数据库和注入技术。"

    def supported_vulns(self) -> list:
        return ["SQL Injection", "Error-based SQLi", "Boolean-based SQLi", "Time-based SQLi", "Union-based SQLi"]

    def capability_statement(self) -> str:
        return "SQL注入自动化工具。输入带参数的URL，自动检测并利用SQL注入。适合：URL参数、登录表单、搜索框等输入点。支持多种注入技术和数据库类型。"

    def check_available(self) -> bool:
        # 如果命令存在，直接可用
        if self.executable and os.access(self.executable, os.X_OK):
            return True
        # 检查pipx安装路径
        pipx_sqlmap = "/root/.local/bin/sqlmap"
        if os.path.exists(pipx_sqlmap):
            return True
        # 检查系统PATH
        import shutil
        return shutil.which("sqlmap") is not None

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL，例如 http://example.com/vuln.php?id=1",
                "required": True
            },
            "data": {
                "type": "str",
                "description": "POST 数据（如果目标是 POST 请求），例如 id=1&name=test",
                "required": False,
                "default": None
            },
            "parameter": {
                "type": "str",
                "description": "指定要测试的参数名 (-p)，例如 'id' 或 'user'",
                "required": False,
                "default": None
            },
            "cookie": {
                "type": "str",
                "description": "自定义 Cookie 字符串",
                "required": False,
                "default": None
            },
            "level": {
                "type": "int",
                "description": "测试深度 (1-5)，越高越全面但越慢",
                "required": False,
                "default": 1
            },
            "risk": {
                "type": "int",
                "description": "风险等级 (1-3)，越高越激进",
                "required": False,
                "default": 1
            },
            "technique": {
                "type": "str",
                "description": "指定注入技术 (B:Boolean, E:Error, U:Union, S:Stacked, T:Time, Q:Inline)",
                "required": False,
                "default": None
            },
            "dbms": {
                "type": "str",
                "description": "指定数据库类型，如 mysql, sqlite",
                "required": False,
                "default": None
            },
            "dump": {
                "type": "bool",
                "description": "是否尝试 dump 数据",
                "required": False,
                "default": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 sqlmap 扫描/利用
        """
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL")

        # [安全修复] 验证 URL 参数，防止命令注入
        is_valid, error_msg = validate_url(url)
        if not is_valid:
            return {"error": f"URL 验证失败: {error_msg}", "success": False}

        # 构建基础命令
        if self.use_script:
            cmd = [self.cmd_path, self.script_path, "-u", url]
        else:
            cmd = [self.cmd_path, "-u", url]

        # 1. 基础必备参数
        cmd.extend(["--batch", "--random-agent"])
        
        # 2. CTF 极速模式优化
        # --smart: 只有在参数确实有迹象时才进行全面测试
        # --threads 10: 最大并发
        # --keep-alive: 保持长连接
        # --null-connection: 只获取响应头大小而不下载 body
        cmd.extend([
            "--threads", "10", 
            "--time-sec", str(params.get("time_sec", 1)),
            "--smart", 
            "--keep-alive", 
            "--null-connection",
            "--flush-session"
        ])

        # 3. 动态可选参数
        if params.get("data"): cmd.extend(["--data", params["data"]])
        if params.get("parameter"): cmd.extend(["-p", params["parameter"]])
        if params.get("cookie"): cmd.extend(["--cookie", params["cookie"]])
        if params.get("dbms"): cmd.extend(["--dbms", params["dbms"]])
        if params.get("technique"): cmd.extend(["--technique", params["technique"]])
        
        # 风险与等级
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        cmd.extend(["--level", str(level), "--risk", str(risk)])

        # 动作参数
        if params.get("dump"): cmd.append("--dump")
        else: cmd.append("--banner") # 默认只跑 banner 确认注入存在

        try:
            raw_result = self._run_command(cmd, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 🚨 [核心修改] 使用 AI 智能分析输出，剔除无效字段，仅保留高价值线索
            analysis_prompt = f"""
分析 sqlmap 的执行输出。你的任务是提取关键安全结论，并为下一步利用提供战术建议。
注意识别：SQL 语法错误（MariaDB/MySQL）、已确认的注入点、数据库指纹。

### 执行命令:
{raw_result.get('command', '')}

### 原始输出 (后 4000 字符):
{stdout[-4000:] if stdout else ""}
{stderr if stderr else ""}

### 输出要求 (JSON):
{{
  "vulnerable": true/false, // 是否发现了漏洞迹象（含报错注入证据）
  "dbms": "识别到的数据库类型",
  "findings": ["注入点详情", "具体的报错特征", "发现的表名/字段名等"],
  "next_step_advice": "战术指引（如：尝试使用十六进制绕过引号限制、dump 关键表等）",
  "summary": "简明扼要的结论"
}}
"""
            analysis_text = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": analysis_prompt}],
                temperature=0.1,
                json_mode=True
            )
            
            # 清理可能的 Markdown 标记
            if "```json" in analysis_text:
                analysis_text = analysis_text.split("```json")[1].split("```")[0]
            elif "```" in analysis_text:
                analysis_text = analysis_text.split("```")[1].split("```")[0]
                
            result = json.loads(analysis_text)
            
            # 保留原始输出用于日志归档，ToolRegistry 会将其存入物理文件并从内存删除
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["success"] = raw_result.get("success", False)
            
            return result

        except Exception as e:
            return {
                "success": False,
                "error": f"AI Analysis failed: {str(e)}",
                "vulnerable": False,
                "summary": "工具执行或 AI 分析失败"
            }