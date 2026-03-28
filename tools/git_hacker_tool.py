# tools/git_hacker_tool.py
# Git 泄露利用工具
import sys
import os
import json
import re
import shutil
import subprocess
from typing import Dict, Any
from tool_framework import CommandLineTool


class GitHackerTool(CommandLineTool):
    """
    GitHacker 封装 - Git 泄露漏洞利用工具
    可以恢复完整的 .git 目录并提取敏感信息

    使用直接复制模式：直接从 thirdparty/Githacker/GitHack.py 运行
    """

    def __init__(self):
        # 智能选择 Python 解释器
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 直接复制模式：设置脚本路径
        docker_path = "/app/data/security_resources/Githacker/GitHack.py"
        local_path = os.path.join(os.getcwd(), "data", "security_resources", "Githacker", "GitHack.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 120

        # 检查是否可用
        self.available = self.script_path is not None and os.path.exists(self.script_path)

    def name(self) -> str:
        return "git-hacker"

    def description(self) -> str:
        return "Git 泄露利用工具，可下载并恢复完整 .git 目录，提取源码和敏感信息"

    def supported_vulns(self) -> list:
        return ["Git Leak", "Source Code Disclosure", "Information Disclosure", "Sensitive File Exposure"]

    def check_available(self) -> bool:
        """检查工具是否可用"""
        return self.available

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "目标 URL（包含 .git 泄露的目录），如 http://example.com/.git/",
                "required": True
            },
            "output_dir": {
                "type": "str",
                "description": "输出目录（默认自动生成）",
                "required": False,
                "default": None
            },
            "depth": {
                "type": "int",
                "description": "克隆深度",
                "required": False,
                "default": 1
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        url = params.get("url") or target
        if not url:
            raise ValueError("必须提供目标 URL")

        # 确保 URL 以 .git 结尾
        if not url.rstrip("/").endswith(".git"):
            url = url.rstrip("/") + "/.git/"

        # 检查脚本是否可用
        if not self.check_available():
            return {
                "success": False,
                "error": "GitHack.py 脚本不可用",
                "vulnerable": False,
                "summary": "工具未安装或脚本路径不存在"
            }

        # 构建命令：python GitHack.py <url>
        cmd = [self.cmd_path, self.script_path, url]

        # 输出目录参数（GitHack.py 不支持 --output，但会创建域名目录）
        # 我们通过环境变量或切换到指定目录来控制输出位置
        output_dir = params.get("output_dir")
        current_dir = os.getcwd()

        try:
            # 如果有输出目录，切换到该目录执行
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                os.chdir(output_dir)

            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 提取下载的文件信息
            downloaded_files = re.findall(r"(?:download|write|save)[^\n]*", stdout, re.IGNORECASE)
            source_files = re.findall(r"[\w/\-]+\.(py|php|js|html|sql|conf|ini|yml|yaml|json|txt|md)", stdout)

            # 获取实际创建的目录（GitHack.py 会创建以域名为名的目录）
            domain_dir = None
            if output_dir:
                # 在输出目录中查找最新创建的目录
                domain_match = re.search(r"Download and parse index file \.\.\.", stdout)
                if domain_match:
                    # 尝试提取域名
                    import urllib.parse
                    parsed = urllib.parse.urlparse(url)
                    domain = parsed.netloc.replace(':', '_')
                    domain_dir = os.path.join(output_dir, domain) if output_dir else domain

            result = {
                "success": raw_result.get("success", False),
                "vulnerable": "git" in stdout.lower() or len(downloaded_files) > 0,
                "downloaded_files": source_files[:20],
                "output_dir": output_dir or domain_dir,
                "summary": f"Git 泄露利用{'成功' if raw_result.get('success') else '失败'}"
            }

            result["raw_output"] = stdout[:2000] if len(stdout) > 2000 else stdout
            if stderr:
                result["stderr"] = stderr[:500]
            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }
        finally:
            # 恢复原始目录
            if output_dir:
                os.chdir(current_dir)