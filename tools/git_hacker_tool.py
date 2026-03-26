# tools/git_hacker_tool.py
# Git 泄露利用工具
import sys
import os
import json
import re
import shutil
from typing import Dict, Any
from tool_framework import CommandLineTool


class GitHackerTool(CommandLineTool):
    """
    GitHacker 封装 - Git 泄露漏洞利用工具
    可以恢复完整的 .git 目录并提取敏感信息
    """

    def __init__(self):
        # 智能选择 Python 解释器
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 智能路径探测 - 多种方式尝试
        self.script_path = None
        self.use_module = False

        # 方式1: 检查是否通过 pipx 安装 (推荐)
        pipx_path = "/root/.local/bin/githacker"
        if os.path.exists(pipx_path):
            self.cmd_path = pipx_path
            self.use_module = True
            self.script_path = "installed"
        elif shutil.which("githacker"):
            self.cmd_path = "githacker"
            self.use_module = True
            self.script_path = "installed"
        else:
            # 方式2: 检查源码目录 (备用)
            docker_path = "/app/thirdparty/git-hacker"
            local_path = os.path.join(os.getcwd(), "thirdparty", "git-hacker")
            self.source_dir = docker_path if os.path.exists(docker_path) else local_path

            if os.path.exists(self.source_dir):
                self.use_module = True
                self.script_path = self.source_dir
            else:
                self.use_module = False
                self.script_path = None

        self.timeout = 120

    def name(self) -> str:
        return "git-hacker"

    def description(self) -> str:
        return "Git 泄露利用工具，可下载并恢复完整 .git 目录，提取源码和敏感信息"

    def supported_vulns(self) -> list:
        return ["Git Leak", "Source Code Disclosure", "Information Disclosure", "Sensitive File Exposure"]

    def check_available(self) -> bool:
        """检查工具是否可用"""
        # 方式1: 已通过 pip 安装
        if shutil.which("githacker"):
            return True
        # 方式2: 源码目录存在且有 githacker 模块
        if hasattr(self, 'source_dir') and os.path.exists(self.source_dir):
            githacker_dir = os.path.join(self.source_dir, "githacker")
            return os.path.exists(githacker_dir)
        return False

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

        # 构建命令
        if shutil.which("githacker"):
            # 使用已安装的 githacker 命令
            cmd = ["githacker", "--url", url]
        else:
            # 使用源码运行
            cmd = [self.cmd_path, "-m", "githacker", "--url", url]
            # 需要切换到源码目录
            if hasattr(self, 'source_dir'):
                os.chdir(self.source_dir)

        # 输出目录
        output_dir = params.get("output_dir")
        if output_dir:
            cmd.extend(["--output", output_dir])

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 提取下载的文件信息
            downloaded_files = re.findall(r"(?:download|write|save)[^\n]*", stdout, re.IGNORECASE)
            source_files = re.findall(r"[\w/\-]+\.(py|php|js|html|sql|conf|ini|yml|yaml|json|txt|md)", stdout)

            result = {
                "success": raw_result.get("success", False),
                "vulnerable": "git" in stdout.lower() or len(downloaded_files) > 0,
                "downloaded_files": source_files[:20],
                "output_dir": output_dir,
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