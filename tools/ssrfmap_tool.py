# tools/ssrfmap_tool.py
"""
SSRFmap Tool - SSRF 漏洞利用工具

功能:
- SSRF 漏洞检测与利用
- 支持多种协议 (http, file, gopher, dict等)
- 云环境元数据获取
- 内网端口扫描

特点:
- 自动化SSRF利用
- 支持多种利用模块
- 可扩展性强

CTF优化:
- 简化参数，一键利用
- 自动选择最佳模块
"""
import os
import sys
import json
import shutil
from typing import Dict, Any, List
from tool_framework import CommandLineTool


class SSRFmapTool(CommandLineTool):
    """
    SSRFmap SSRF利用工具封装

    使用方式: 通过 SSRF 参数触发，自动利用
    """

    # 前置条件
    REQUIRES_CREDENTIALS = False
    REQUIRES_SHELL_SESSION = False
    TOOL_CATEGORY = "attacker"  # 攻击工具

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # 脚本路径
        docker_path = "/app/thirdparty/SSRFmap/ssrfmap.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "SSRFmap", "ssrfmap.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 180

    def name(self) -> str:
        return "ssrfmap"

    def description(self) -> str:
        return "SSRF漏洞利用工具，支持多种协议、云环境元数据获取、内网扫描。"

    def supported_vulns(self) -> list:
        return [
            "SSRF",
            "Server Side Request Forgery",
            "Cloud Metadata",
            "Internal Port Scan",
            "File Read"
        ]

    def capability_statement(self) -> str:
        return "SSRF利用工具。输入存在SSRF的URL和参数，自动利用获取敏感信息。适合：SSRF漏洞验证、内网探测、云环境利用。分析兵节点使用。"

    def check_available(self) -> bool:
        """检查 SSRFmap 是否可用"""
        if not shutil.which("python3" if os.path.exists("/.dockerenv") else "python"):
            return False
        return self.script_path is not None and os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "url": {
                "type": "str",
                "description": "存在SSRF的目标URL",
                "required": True
            },
            "param": {
                "type": "str",
                "description": "SSRF注入的参数名",
                "required": True
            },
            "module": {
                "type": "str",
                "description": "利用模块: readfiles, aws, gce, azure, ports, all",
                "required": False,
                "default": "readfiles"
            },
            "target_ssrf": {
                "type": "str",
                "description": "SSRF请求的目标地址 (如 http://169.254.169.254/)",
                "required": False
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        """
        执行 SSRFmap
        """
        url = params.get("url") or target
        param = params.get("param")
        module = params.get("module", "readfiles")
        target_ssrf = params.get("target_ssrf")

        if not url:
            return {"error": "必须提供目标URL", "success": False}
        if not param:
            return {"error": "必须提供SSRF参数名", "success": False}

        if not self.check_available():
            return {
                "error": "SSRFmap 不可用，请检查安装",
                "success": False
            }

        # 构建命令
        cmd = [self.cmd_path, self.script_path]
        cmd.extend(["-r", url])
        cmd.extend(["-p", param])
        cmd.extend(["-m", module])

        if target_ssrf:
            cmd.extend(["--lhost", target_ssrf])

        print(f"[SSRFmap] Executing: {' '.join(cmd)}")

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 解析结果
            findings = []
            lines = stdout.split("\n")

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # 检测敏感信息
                if any(keyword in line.lower() for keyword in ["secret", "key", "token", "password", "credential", "metadata"]):
                    findings.append(line)

            # 判断是否成功
            success = raw_result.get("success", False) or len(findings) > 0

            return {
                "success": success,
                "vulnerable": len(findings) > 0,
                "url": url,
                "param": param,
                "module": module,
                "findings": findings[:20],  # 限制输出
                "summary": f"SSRF利用{'成功' if findings else '完成'}，发现 {len(findings)} 条敏感信息",
                "stdout": stdout
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "url": url
            }


def register():
    """注册 SSRFmap 工具"""
    from tool_framework import ToolRegistry
    ToolRegistry.register(SSRFmapTool())