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
    """

    def __init__(self):
        # 智能选择 Python 解释器
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 智能路径探测 - 多种方式尝试
        self.script_path = None
        self.use_pipx = False
        self.use_module = False
        self.available = False
        self._install_attempted = False

        # 方式1: 检查 pipx 安装路径 (多种可能的可执行文件名)
        pipx_paths = [
            "/root/.local/bin/git-hacker",  # 带连字符
            "/root/.local/bin/githacker",   # 不带连字符
            "/opt/venv/bin/git-hacker",     # venv路径
            "/opt/venv/bin/githacker",
        ]
        for path in pipx_paths:
            if os.path.exists(path):
                self.cmd_path = path
                self.use_pipx = True
                self.script_path = path
                self.available = True
                break

        # 方式2: 检查系统 PATH
        if not self.available:
            for name in ["git-hacker", "githacker"]:
                path = shutil.which(name)
                if path:
                    self.cmd_path = path
                    self.use_pipx = True
                    self.script_path = path
                    self.available = True
                    break

        # 方式3: 检查源码目录 (备用)
        if not self.available:
            docker_path = "/app/thirdparty/git-hacker"
            local_path = os.path.join(os.getcwd(), "thirdparty", "git-hacker") if os.getcwd() else ""
            self.source_dir = docker_path if os.path.exists(docker_path) else local_path

            if os.path.exists(self.source_dir):
                # 检查是否有 githacker.py 或 githacker 目录
                githacker_py = os.path.join(self.source_dir, "githacker.py")
                githacker_dir = os.path.join(self.source_dir, "githacker")
                if os.path.exists(githacker_py) or os.path.exists(githacker_dir):
                    self.use_module = True
                    self.script_path = self.source_dir
                    self.available = True

        # 方式4: 尝试pip安装（运行时安装）
        if not self.available:
            self._try_install()

        self.timeout = 120

    def _try_install(self):
        """尝试运行时安装git-hacker"""
        if self._install_attempted:
            return
        self._install_attempted = True

        try:
            print("[git-hacker] 尝试运行时安装...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "git-hacker", "-q"],
                capture_output=True,
                timeout=60
            )
            if result.returncode == 0:
                # 再次检查
                for name in ["git-hacker", "githacker"]:
                    path = shutil.which(name)
                    if path:
                        self.cmd_path = path
                        self.use_pipx = True
                        self.script_path = path
                        self.available = True
                        print(f"[git-hacker] 安装成功: {path}")
                        break
        except Exception as e:
            print(f"[git-hacker] 安装失败: {e}")

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