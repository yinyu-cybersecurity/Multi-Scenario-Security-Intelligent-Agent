# tools/dirsearch_tool.py
import sys
import json
import re
import os
from typing import Dict, Any
from tool_framework import CommandLineTool
from llm_client import llm_client
from config import config

class DirsearchTool(CommandLineTool):
    """
    Dirsearch 封装 - Web 路径/目录爆破工具
    """

    def __init__(self):
        import sys
        import os

        # 智能选择 Python 解释器
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 智能路径探测
        docker_path = "/app/thirdparty/dirsearch/dirsearch.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "dirsearch", "dirsearch.py")

        # 检查多个可能的路径
        possible_paths = [
            docker_path,
            local_path,
            "/app/thirdparty/dirsearch/dirsearch.py",
            "thirdparty/dirsearch/dirsearch.py",
        ]

        self.script_path = None
        for path in possible_paths:
            if os.path.exists(path):
                self.script_path = path
                break

        # 如果都不存在，尝试使用系统安装的 dirsearch
        if not self.script_path:
            import shutil
            if shutil.which("dirsearch"):
                self.script_path = "dirsearch"
                self.is_system = True
            else:
                self.script_path = docker_path  # 保留默认值，运行时会报错
                self.is_system = False
        else:
            self.is_system = False

    def name(self) -> str:
        return "dirsearch"

    def description(self) -> str:
        return "高级 Web 路径扫描工具，支持多线程、递归扫描、自定义字典和状态码过滤"

    def supported_vulns(self) -> list:
        return ["Information Disclosure", "Hidden Paths", "Backup Files", "Admin Panels", "API Endpoints"]

    def capability_statement(self) -> str:
        return "目录扫描工具。发现隐藏路径、备份文件、管理后台、API端点。适合：无明确漏洞方向时的资产发现。"

    def check_available(self) -> bool:
        """检查 dirsearch 是否可用"""
        import shutil

        # 如果是系统命令
        if hasattr(self, 'is_system') and self.is_system:
            return shutil.which("dirsearch") is not None

        # 检查脚本文件是否存在
        if self.script_path is None:
            return False

        if not os.path.exists(self.script_path):
            return False

        # 还要检查 Python 解释器是否存在
        if not shutil.which(self.cmd_path):
            return False

        return True

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL，例如 http://example.com",
                "required": True
            },
            "extensions": {
                "type": "str",
                "description": "扫描的文件扩展名，逗号分隔（例如 php,asp,html）",
                "required": False,
                "default": "php,html,js"
            },
            "wordlist": {
                "type": "str",
                "description": "自定义字典文件路径（不指定则使用默认字典）",
                "required": False,
                "default": None
            },
            "threads": {
                "type": "int",
                "description": "线程数（默认 30）",
                "required": False,
                "default": 30
            },
            "recursive": {
                "type": "bool",
                "description": "是否递归扫描发现的目录",
                "required": False,
                "default": False
            },
            "max_recursion_depth": {
                "type": "int",
                "description": "最大递归深度",
                "required": False,
                "default": 1
            },
            "include_status": {
                "type": "str",
                "description": "只显示这些状态码的结果（逗号分隔，例如 200,301,403）",
                "required": False,
                "default": None
            },
            "exclude_status": {
                "type": "str",
                "description": "排除这些状态码（例如 404,500）",
                "required": False,
                "default": "404"
            },
            "random_agent": {
                "type": "bool",
                "description": "是否使用随机 User-Agent",
                "required": False,
                "default": True
            },
            "timeout": {
                "type": "int",
                "description": "连接超时时间（秒）",
                "required": False,
                "default": 10
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL")

        # 检查脚本是否存在
        if not self.check_available():
            return {
                "success": False,
                "error": f"dirsearch 脚本不存在: {self.script_path}",
                "vulnerable": False,
                "summary": "工具不可用"
            }

        # 构建命令
        if hasattr(self, 'is_system') and self.is_system:
            cmd = ["dirsearch", "-u", url]
        else:
            cmd = [self.cmd_path, self.script_path, "-u", url]

        # 1. 强制性能优化参数
        # -q: 静默模式，只输出结果
        # --random-agent: 随机 UA
        # --no-color: 纯文本输出
        # --full-url: 输出完整路径
        cmd.extend(["-q", "--random-agent", "--no-color", "--full-url"])

        # 2. 状态码与长度过滤 (CTF 比赛中非常重要)
        # 排除 404, 500, 503 等无效页面
        exclude_status = params.get("exclude_status", "400,404,500,502,503")
        cmd.extend(["-x", exclude_status])
        
        # 排除特定长度（例如 0 字节，或者 WAF 统一返回的长度）
        # 这里默认排除 0 字节和常见的空页面长度
        cmd.extend(["--exclude-sizes", "0b,1b"])

        # 3. 字典与扩展名
        extensions = params.get("extensions", "php,html,js,txt,zip")
        cmd.extend(["-e", extensions])

        # 4. 线程与递归限制
        # 为了防止卡死，我们将默认线程稍微降低到 20，但在关键路径上更准
        threads = params.get("threads", 20)
        cmd.extend(["-t", str(threads)])

        # 除非明确要求，否则禁止递归
        if params.get("recursive", False):
            cmd.append("-r")
            depth = params.get("max_recursion_depth", 1)
            cmd.extend(["-R", str(depth)])

        # 5. 连接超时设置
        timeout = params.get("timeout", 5) # 降低连接等待时间
        cmd.extend(["--timeout", str(timeout)])

        # 6. 使用 --minimal-mode (如果 dirsearch 版本支持) 
        # 或者通过字典限制来实现极速扫描
        # cmd.append("--minimal-mode") 

        try:
            # 执行命令 - 使用流式输出，设置工具层的物理超时 (120秒)
            raw_result = self._run_command(cmd, timeout=120, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 🚨 [核心修改] 使用 AI 智能分析扫描结果，提取高价值路径
            analysis_prompt = f"""
分析 dirsearch 的执行输出。你的任务是识别出最有价值的路径（如 200/301 状态码且内容长度异常的页面）。
剔除无意义的 404 或误报，精炼扫描结果。

### 扫描目标:
{url}

### 原始输出 (前 5000 字符):
{stdout[:5000]}
{stderr if stderr else ""}

### 输出要求 (JSON):
{{
  "vulnerable": true/false, // 是否发现了敏感路径或配置泄露
  "critical_paths": [
    {{ "url": "路径", "status": 状态码, "reason": "为什么这个路径重要" }}
  ],
  "next_step_advice": "建议下一步操作（如：访问管理后台、查看敏感配置文件等）",
  "summary": "扫描结果摘要"
}}
"""
            analysis_text = llm_client.call_chat_completion(
                model=config.ANALYST_MODEL,
                messages=[{"role": "user", "content": analysis_prompt}],
                temperature=0.1,
                json_mode=True
            )
            
            if "```json" in analysis_text:
                analysis_text = analysis_text.split("```json")[1].split("```")[0]
            elif "```" in analysis_text:
                analysis_text = analysis_text.split("```")[1].split("```")[0]
                
            result = json.loads(analysis_text)
            
            # 保留原始输出用于日志归档
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